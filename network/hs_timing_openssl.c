// hs_timing_openssl.c - ../pico/sketches/mqtt_tls_bench/hs_timing.c for the OpenSSL client (mqtt_tls_timer, Linux):
//   the same four sums (hs_timing.h), reset per connection, timing the calls libssl makes into libcrypto during a
//   TLS 1.3 handshake. The executable defines those functions itself; the dynamic linker binds libssl's calls to the
//   executable's copies first (ld exports them because libssl references them), and each one forwards to libcrypto's
//   via dlsym(RTLD_NEXT). macOS binds libssl to libcrypto directly, so no columns there.
//     keygen  EVP_PKEY_keygen / EVP_PKEY_generate: the key share (a hybrid group is one provider key: one call)
//     derive  EVP_PKEY_derive (ECDHE) / EVP_PKEY_decapsulate (ML-KEM and hybrids)
//     verify  X509_verify_cert on the broker's chain (the CA's signature) + EVP_DigestVerify (its CertificateVerify);
//             not the X509_verify_cert that builds the client's own chain to send (no SSL attached to that one)
//     sign    EVP_DigestSign (the client's CertificateVerify, mTLS)
//   Only the outermost call counts (depth), and only calls that do the work: libssl first asks for lengths with a
//   NULL output buffer.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "hs_timing.h"

static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }

hs_times_t hs_t;
static int depth;

#define WRAP(cat, name, params, args, counts)                                           \
  int name params {                                                                     \
    static int (*real) params;                                                          \
    if (!real) real = (int (*) params)dlsym(RTLD_NEXT, #name);                          \
    double t0 = depth++ ? 0 : now_us();                                                 \
    int r = real args;                                                                  \
    if (--depth == 0 && (counts)) { hs_t.us[cat] += now_us() - t0; hs_t.n[cat]++; }      \
    return r;                                                                           \
  }
typedef const unsigned char cuc;
WRAP(HS_KEYGEN, EVP_PKEY_keygen, (EVP_PKEY_CTX *c, EVP_PKEY **k), (c, k), 1)
WRAP(HS_KEYGEN, EVP_PKEY_generate, (EVP_PKEY_CTX *c, EVP_PKEY **k), (c, k), 1)
WRAP(HS_DERIVE, EVP_PKEY_derive, (EVP_PKEY_CTX *c, unsigned char *k, size_t *kl), (c, k, kl), k != NULL)
WRAP(HS_DERIVE, EVP_PKEY_decapsulate, (EVP_PKEY_CTX *c, unsigned char *k, size_t *kl, cuc *w, size_t wl),
     (c, k, kl, w, wl), k != NULL)
WRAP(HS_VERIFY, X509_verify_cert, (X509_STORE_CTX *c), (c),
     X509_STORE_CTX_get_ex_data(c, SSL_get_ex_data_X509_STORE_CTX_idx()) != NULL)
WRAP(HS_VERIFY, EVP_DigestVerify, (EVP_MD_CTX *c, cuc *s, size_t sl, cuc *m, size_t ml), (c, s, sl, m, ml), 1)
WRAP(HS_SIGN, EVP_DigestSign, (EVP_MD_CTX *c, unsigned char *s, size_t *sl, cuc *m, size_t ml), (c, s, sl, m, ml),
     s != NULL)
