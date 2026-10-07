// test.cpp - the Pico's wolfSSL with SNOVA in Falcon-512's place (-DWB_SNOVA<set>) on the host (run.sh), against the
// round 3 broker's TLS and mTLS listeners for that set: both connect and get a CONNACK, a changed CA key is refused.
// Exit 1 on any failure.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

extern "C" int wb_rand_block(unsigned char *out, unsigned int n) {  // the sketch's hardware RNG, here the OS's
  for (; n; ) { unsigned k = n < 256 ? n : 256; if (getentropy(out, k)) return -1; out += k; n -= k; }
  return 0;
}
static std::vector<uint8_t> slurp(const std::string &p) {
  std::vector<uint8_t> v; FILE *f = fopen(p.c_str(), "rb");
  if (!f) { fprintf(stderr, "cannot read %s\n", p.c_str()); exit(1); }
  for (int c; (c = fgetc(f)) != EOF;) v.push_back((uint8_t)c);
  fclose(f); return v;
}
static int fails;
static void check(bool ok, const char *what) { printf("[%s] %s\n", ok ? "+" : "-", what); fails += !ok; }
static double now_ms() { timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }

static int io_send(WOLFSSL *, char *b, int n, void *c) { int r = (int)send(*(int *)c, b, n, 0); return r > 0 ? r : WOLFSSL_CBIO_ERR_CONN_CLOSE; }
static int io_recv(WOLFSSL *, char *b, int n, void *c) { int r = (int)recv(*(int *)c, b, n, 0); return r > 0 ? r : WOLFSSL_CBIO_ERR_CONN_CLOSE; }
// TLS 1.3 to 127.0.0.1:port (X25519MLKEM768), the client certificate when given, then MQTT CONNECT -> 0 on a CONNACK
static int connect_mqtt(int port, const std::vector<uint8_t> &ca, const std::vector<uint8_t> *crt, const std::vector<uint8_t> *key) {
  WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  int r = wolfSSL_CTX_load_verify_buffer(ctx, ca.data(), (long)ca.size(), WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS ? 0 : -1;
  if (!r && crt && (wolfSSL_CTX_use_certificate_buffer(ctx, crt->data(), (long)crt->size(), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
                    wolfSSL_CTX_use_PrivateKey_buffer(ctx, key->data(), (long)key->size(), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS))
    r = -2;
  if (r) { printf("    %s did not load\n", r == -1 ? "CA.crt" : "client.crt / client.key"); wolfSSL_CTX_free(ctx); return r; }
  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
  wolfSSL_CTX_SetIORecv(ctx, io_recv); wolfSSL_CTX_SetIOSend(ctx, io_send);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port); a.sin_addr.s_addr = htonl(0x7F000001);
  if (connect(fd, (sockaddr *)&a, sizeof a)) { printf("    no listener on %d\n", port); return -3; }
  WOLFSSL *s = wolfSSL_new(ctx);
  wolfSSL_SetIOReadCtx(s, &fd); wolfSSL_SetIOWriteCtx(s, &fd);
  int g = WOLFSSL_X25519MLKEM768; wolfSSL_set_groups(s, &g, 1); wolfSSL_UseKeyShare(s, g);
  double t0 = now_ms();
  r = wolfSSL_connect(s) == WOLFSSL_SUCCESS ? 0 : wolfSSL_get_error(s, 0);
  double hs = now_ms() - t0;
  static const uint8_t conn[] = {0x10, 13, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 1, 't'};  // MQTT 3.1.1, client "t"
  uint8_t ack[4] = {0};
  if (!r && (wolfSSL_write(s, conn, sizeof conn) != (int)sizeof conn || wolfSSL_read(s, ack, 4) != 4 ||
             ack[0] != 0x20 || ack[3] != 0))
    r = wolfSSL_get_error(s, 0) ? wolfSSL_get_error(s, 0) : -4;  // the broker refused the client after the handshake
  char e[WOLFSSL_MAX_ERROR_SZ];
  printf("    port %d%s: %s (handshake %.1f ms)\n", port, crt ? " +client cert" : "", r ? wolfSSL_ERR_error_string(r, e) : "CONNACK", hs);
  wolfSSL_free(s); close(fd); wolfSSL_CTX_free(ctx);
  return r;
}

int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "usage: test <dir with CA.der client.der client.key.der CA_bad.der> <TLS port> <mTLS port>\n"); return 2; }
  std::string d = argv[1];
  wolfSSL_Init();
  wolfSSL_Debugging_ON();  // only with -DDEBUG_WOLFSSL (run.sh WB_EXTRA)
  auto ca = slurp(d + "/CA.der"), bad = slurp(d + "/CA_bad.der"), crt = slurp(d + "/client.der"), key = slurp(d + "/client.key.der");
  check(connect_mqtt(atoi(argv[2]), ca, nullptr, nullptr) == 0, "TLS: the broker's SNOVA chain verifies");
  check(connect_mqtt(atoi(argv[3]), ca, &crt, &key) == 0, "mTLS: wolfSSL signs with the SNOVA client key, the broker accepts");
  check(connect_mqtt(atoi(argv[2]), bad, nullptr, nullptr) != 0, "TLS with one bit of CA.crt's public key changed: refused");
  printf(fails ? "[-] %d check(s) failed\n" : "[+] all checks passed\n", fails);
  return fails ? 1 : 0;
}
