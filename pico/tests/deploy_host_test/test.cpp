// test.cpp - deploy_wolf.h with the Pico's wolfSSL settings on the host (run.sh): TLS checks against local listeners,
// the signed trust-anchor update, ML-DSA-44 signatures both ways with OpenSSL. Exit 1 on any failure.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <vector>
#include "deploy_wolf.h"

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

static int io_send(WOLFSSL *, char *b, int n, void *c) { int r = (int)send(*(int *)c, b, n, 0); return r > 0 ? r : WOLFSSL_CBIO_ERR_CONN_CLOSE; }
static int io_recv(WOLFSSL *, char *b, int n, void *c) { int r = (int)recv(*(int *)c, b, n, 0); return r > 0 ? r : WOLFSSL_CBIO_ERR_CONN_CLOSE; }
// one TLS 1.3 handshake to 127.0.0.1:port with the CA, optionally the CRL and a name -> wolfSSL's error (0 = success)
static int handshake(int port, const std::vector<uint8_t> &ca, const std::vector<uint8_t> *crl, const char *name) {
  WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  wolfSSL_CTX_load_verify_buffer(ctx, ca.data(), (long)ca.size(), WOLFSSL_FILETYPE_ASN1);
  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
  wolfSSL_CTX_SetIORecv(ctx, io_recv); wolfSSL_CTX_SetIOSend(ctx, io_send);
  if (crl && dp_checks_ctx(ctx, crl->data(), crl->size())) { printf("    CRL not loaded\n"); return -999; }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port); a.sin_addr.s_addr = htonl(0x7F000001);
  if (connect(fd, (sockaddr *)&a, sizeof a)) { printf("    no listener on %d\n", port); return -998; }
  WOLFSSL *s = wolfSSL_new(ctx);
  wolfSSL_SetIOReadCtx(s, &fd); wolfSSL_SetIOWriteCtx(s, &fd);
  int g = WOLFSSL_X25519MLKEM768; wolfSSL_set_groups(s, &g, 1); wolfSSL_UseKeyShare(s, g);
  if (name && dp_checks_ssl(s, name)) { printf("    the name %s was not set\n", name); return -997; }
  int r = wolfSSL_connect(s) == WOLFSSL_SUCCESS ? 0 : wolfSSL_get_error(s, 0);
  char e[WOLFSSL_MAX_ERROR_SZ];
  printf("    port %d%s%s%s: %s\n", port, crl ? " +CRL" : "", name ? " name=" : "", name ? name : "",
         r ? wolfSSL_ERR_error_string(r, e) : "handshake OK");
  wolfSSL_free(s); close(fd); wolfSSL_CTX_free(ctx);
  return r;
}

int main(int argc, char **argv) {
  if (argc != 5) { fprintf(stderr, "usage: test <certs/DEPLOY> <port server> <port revoked> <port expired>\n"); return 2; }
  std::string d = argv[1];
  int ps = atoi(argv[2]), pr = atoi(argv[3]), pe = atoi(argv[4]);
  wolfSSL_Init();
  auto ca = slurp("CA.der"), crl = slurp("CA.crl.der"), srv = slurp("server.der"), key = slurp("client.der");
  auto upd = slurp(d + "/update.pub"), ta = slurp(d + "/ta_update.bin");
  auto msg = slurp("msg"), ssig = slurp("msg.server.sig");

  puts("TLS checks (dates are always on in this build):");
  check(handshake(ps, ca, &crl, "127.0.0.1") == 0, "server.crt with the CRL and the right name: accepted");
  check(handshake(ps, ca, &crl, "192.0.2.1") != 0, "server.crt with a wrong name: refused");
  check(handshake(ps, ca, &crl, "192.168.50.132") == 0, "server.crt with the broker's LAN IP (in its SAN): accepted");
  check(handshake(pr, ca, nullptr, nullptr) == 0, "revoked.crt without the CRL: accepted (the CRL is what refuses it)");
  check(handshake(pr, ca, &crl, nullptr) != 0, "revoked.crt with the CRL: refused");
  check(handshake(pe, ca, nullptr, nullptr) != 0, "expired.crt: refused (certificate dates)");

  puts("Trust-anchor update:");
  size_t n = 0;
  int off = dp_ta_verify(ta.data(), ta.size(), upd.data(), upd.size(), &n);
  check(off == 6 && n == ca.size() && !memcmp(ta.data() + off, ca.data(), n), "ta_update.bin verifies and carries CA.crt");
  for (size_t i : {(size_t)5, (size_t)100, ta.size() - 1}) {  // the length, the CA, the signature
    auto bad = ta; bad[i] ^= 1;
    check(dp_ta_verify(bad.data(), bad.size(), upd.data(), upd.size(), &n) < 0, "a changed byte: refused");
  }

  puts("ML-DSA-44 between wolfCrypt and OpenSSL:");
  dp_key sk = {}, pk = {};
  WC_RNG rng; wc_InitRng(&rng);
  check(dp_key_cert(&pk, srv.data(), srv.size(), ca.data(), ca.size()) == 0, "server.crt checks against CA.crt; its key loads");
  check(dp_verify(&pk, msg.data(), msg.size(), ssig.data(), ssig.size()) == 0, "wolfCrypt verifies OpenSSL's signature");
  check(dp_key_private(&sk, key.data(), key.size()) == 0, "client.key (PKCS#8) loads for signing");
  uint8_t sig[2420]; size_t sl = sizeof sig;
  check(dp_sign(&sk, &rng, msg.data(), msg.size(), sig, &sl) == 0 && sl == 2420, "wolfCrypt signs (2,420 B)");
  FILE *f = fopen("msg.device.sig", "wb"); fwrite(sig, 1, sl, f); fclose(f);  // run.sh has OpenSSL verify it
  dp_key_free(&sk); dp_key_free(&pk); wc_FreeRng(&rng);
  printf(fails ? "[-] %d check(s) failed\n" : "[+] all checks passed\n", fails);
  return fails ? 1 : 0;
}
