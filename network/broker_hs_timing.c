// broker_hs_timing.c - the broker's side of each TLS handshake, measured inside Mosquitto without changing it: a
//   library preloaded into the broker (Linux LD_PRELOAD, macOS DYLD_INSERT_LIBRARIES; mqtt_bench.py does this when
//   it starts the brokers) that times the OpenSSL calls Mosquitto makes while a connection is still handshaking.
//   Mosquitto drives the server handshake from SSL_accept (2.0) or SSL_read / SSL_write (2.1), so the sum of those
//   calls, from the first until the handshake is finished, is the broker's own work: network waits fall between calls.
//   Inside them it also sums the crypto, as hs_timing_openssl.c does on the client:
//     keygen  EVP_PKEY_keygen (an ECDHE share)      encaps  EVP_PKEY_encapsulate (ML-KEM and hybrid groups)
//     derive  EVP_PKEY_derive (ECDHE)               sign    EVP_DigestSign (the broker's CertificateVerify)
//     verify  X509_verify_cert on the client's chain + EVP_DigestVerify (its CertificateVerify): mTLS only
//   Each finished handshake appends one line to $BROKER_HS_LOG (one write: the brokers share the file):
//     unix_time,client_ip,port,group,total_us,keygen_us,encaps_us,derive_us,sign_us,verify_us,calls
//   Without BROKER_HS_LOG it only passes calls through.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef __APPLE__  // interposing: the replacement is w_<f>; calling <f> from this library reaches OpenSSL's own
#define DEF(ret, name, params, args)                                                                          \
  static ret w_##name params;                                                                                 \
  __attribute__((used, section("__DATA,__interpose"))) static const struct { const void *w, *o; } ip_##name = \
      {(const void *)w_##name, (const void *)name};                                                           \
  static ret real_##name params { return name args; }                                                         \
  static ret w_##name params
#else             // preloading: this library's <f> wins; OpenSSL's comes from the next object
#define DEF(ret, name, params, args)                                                                          \
  static ret w_##name params;                                                                                 \
  ret name params { return w_##name args; }                                                                   \
  static ret real_##name params {                                                                             \
    static ret (*f) params;                                                                                   \
    if (!f) f = (ret (*) params)dlsym(RTLD_NEXT, #name);                                                      \
    return f args;                                                                                            \
  }                                                                                                           \
  static ret w_##name params
#endif

enum { T_TOTAL, T_KEYGEN, T_ENCAPS, T_DERIVE, T_SIGN, T_VERIFY, T_N };
typedef struct { const SSL *s; double t[T_N]; int calls; } slot_t;
static slot_t slots[64], *cur;  // Mosquitto is single-threaded: one handshake call at a time
static int logfd = -2, depth;

static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }
static int logging(void) {
  if (logfd == -2) logfd = getenv("BROKER_HS_LOG") ? open(getenv("BROKER_HS_LOG"), O_WRONLY | O_CREAT | O_APPEND, 0644) : -1;
  return logfd >= 0;
}
static slot_t *slot(const SSL *s) {
  slot_t *free_one = NULL;
  for (int i = 0; i < 64; i++) {
    if (slots[i].s == s) return &slots[i];
    if (!slots[i].s && !free_one) free_one = &slots[i];
  }
  if (free_one) { memset(free_one, 0, sizeof *free_one); free_one->s = s; }
  return free_one;
}
static void emit(SSL *s, slot_t *x) {
  char ip[64] = "?", line[320];
  struct sockaddr_storage a; socklen_t al = sizeof a;
  int fd = SSL_get_fd(s), port = 0;
  if (fd >= 0 && !getpeername(fd, (struct sockaddr *)&a, &al))
    inet_ntop(a.ss_family, a.ss_family == AF_INET6 ? (void *)&((struct sockaddr_in6 *)&a)->sin6_addr
                                                   : (void *)&((struct sockaddr_in *)&a)->sin_addr, ip, sizeof ip);
  al = sizeof a;
  if (fd >= 0 && !getsockname(fd, (struct sockaddr *)&a, &al))
    port = ntohs(a.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&a)->sin6_port : ((struct sockaddr_in *)&a)->sin_port);
  const char *g = SSL_group_to_name(s, SSL_get_negotiated_group(s));
  int n = snprintf(line, sizeof line, "%ld,%s,%d,%s,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%d\n", (long)time(NULL), ip, port,
                   g ? g : "?", x->t[T_TOTAL], x->t[T_KEYGEN], x->t[T_ENCAPS], x->t[T_DERIVE], x->t[T_SIGN],
                   x->t[T_VERIFY], x->calls);
  if (write(logfd, line, (size_t)n) < 0) {}
  x->s = NULL;
}
// one handshake step: time it while the handshake is unfinished; emit when it just finished
#define STEP(s, call)                                                                                         \
  do {                                                                                                        \
    if (!logging() || SSL_is_init_finished(s) || !(cur = slot(s))) return call;                               \
    slot_t *x = cur;                                                                                          \
    double t0 = now_us();                                                                                     \
    int r = call;                                                                                             \
    x->t[T_TOTAL] += now_us() - t0; x->calls++;                                                               \
    cur = NULL;                                                                                               \
    if (SSL_is_init_finished(s)) emit(s, x);                                                                  \
    return r;                                                                                                 \
  } while (0)

DEF(int, SSL_accept, (SSL *s), (s)) { STEP(s, real_SSL_accept(s)); }
DEF(int, SSL_do_handshake, (SSL *s), (s)) { STEP(s, real_SSL_do_handshake(s)); }
DEF(int, SSL_read, (SSL *s, void *b, int n), (s, b, n)) { STEP(s, real_SSL_read(s, b, n)); }
DEF(int, SSL_write, (SSL *s, const void *b, int n), (s, b, n)) { STEP(s, real_SSL_write(s, b, n)); }
DEF(void, SSL_free, (SSL *s), (s)) {
  for (int i = 0; i < 64; i++) if (slots[i].s == s) slots[i].s = NULL;  // a handshake that never finished
  real_SSL_free(s);
}

// the crypto inside a handshake step: only the outermost call; libssl asks for lengths first with NULL outputs
#define CRYPTO(cat, call, counts)                                                                             \
  do {                                                                                                        \
    if (!cur || depth) return call;                                                                           \
    slot_t *x = cur;                                                                                          \
    double t0 = now_us();                                                                                     \
    depth++;                                                                                                  \
    int r = call;                                                                                             \
    depth--;                                                                                                  \
    if (counts) x->t[cat] += now_us() - t0;                                                                   \
    return r;                                                                                                 \
  } while (0)
typedef const unsigned char cuc;
DEF(int, EVP_PKEY_keygen, (EVP_PKEY_CTX *c, EVP_PKEY **k), (c, k)) { CRYPTO(T_KEYGEN, real_EVP_PKEY_keygen(c, k), 1); }
DEF(int, EVP_PKEY_encapsulate, (EVP_PKEY_CTX *c, unsigned char *w, size_t *wl, unsigned char *k, size_t *kl),
    (c, w, wl, k, kl)) { CRYPTO(T_ENCAPS, real_EVP_PKEY_encapsulate(c, w, wl, k, kl), w != NULL); }
DEF(int, EVP_PKEY_derive, (EVP_PKEY_CTX *c, unsigned char *k, size_t *kl), (c, k, kl)) {
  CRYPTO(T_DERIVE, real_EVP_PKEY_derive(c, k, kl), k != NULL);
}
DEF(int, EVP_DigestSign, (EVP_MD_CTX *c, unsigned char *s, size_t *sl, cuc *m, size_t ml), (c, s, sl, m, ml)) {
  CRYPTO(T_SIGN, real_EVP_DigestSign(c, s, sl, m, ml), s != NULL);
}
DEF(int, EVP_DigestVerify, (EVP_MD_CTX *c, cuc *s, size_t sl, cuc *m, size_t ml), (c, s, sl, m, ml)) {
  CRYPTO(T_VERIFY, real_EVP_DigestVerify(c, s, sl, m, ml), 1);
}
DEF(int, X509_verify_cert, (X509_STORE_CTX *c), (c)) {  // the client's chain only, not the broker building its own
  CRYPTO(T_VERIFY, real_X509_verify_cert(c), X509_STORE_CTX_get_ex_data(c, SSL_get_ex_data_X509_STORE_CTX_idx()) != NULL);
}
