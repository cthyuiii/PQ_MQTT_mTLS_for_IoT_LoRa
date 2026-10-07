// Runs the Pico's KEM-exchange code (pico/sketches/mqtt_tls_bench/kem_wolf.h, wolfCrypt) on the host against the responder's
// side as network/mqtt_tls_timer.c does it (liboqs encapsulation, OpenSSL X25519): every KEM must agree on
// the shared secret, and its sizes must be the responder's.
#include <wolfssl/options.h>
#define KW_LIBOQS  // + HQC-1 through liboqs, as the KEM-exchange firmware
#include "kem_wolf.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <stdio.h>

static int x25519(uint8_t pub[32], uint8_t ss[32], const uint8_t peer[32]) {  // ephemeral key + DH, as kem_encaps
  EVP_PKEY *e = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"), *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
  EVP_PKEY_CTX *c = e ? EVP_PKEY_CTX_new(e, NULL) : NULL;
  size_t a = 32, b = 32;
  int ok = c && p && EVP_PKEY_get_raw_public_key(e, pub, &a) == 1 && EVP_PKEY_derive_init(c) == 1 &&
           EVP_PKEY_derive_set_peer(c, p) == 1 && EVP_PKEY_derive(c, ss, &b) == 1;
  EVP_PKEY_CTX_free(c); EVP_PKEY_free(e); EVP_PKEY_free(p);
  return ok;
}

int main() {
  static const size_t want[KW_N][3] = {{800, 768, 32}, {1184, 1088, 32}, {1568, 1568, 32}, {32, 32, 32}, {1216, 1120, 64},
                                       {2241, 4433, 32}};
  WC_RNG rng;
  int bad = wc_InitRng(&rng) != 0;
  for (int i = 0; i < KW_N; i++) {
    static kw_state s;
    uint8_t pk[KW_MAX], ct[KW_MAX], dev[64], resp[64];
    int ok = kw_init(&s, i, &rng) == 0 && s.pk == want[i][0] && s.ct == want[i][1] && s.ss == want[i][2];
    for (int t = 0; ok && t < 20; t++) {  // fresh keys each time, as the Pico's exchanges
      ok = kw_keypair(&s, pk) == 0;
      if (ok && (s.k->mlkem >= 0 || s.k->oqs)) {
        OQS_KEM *q = OQS_KEM_new(s.k->oqs ? s.k->oqs : s.k->x25519 ? "ML-KEM-768" : s.k->name);
        ok = q && OQS_KEM_encaps(q, ct, resp, pk) == OQS_SUCCESS;
        OQS_KEM_free(q);
      }
      if (ok && s.k->x25519) ok = x25519(ct + s.ct - 32, resp + s.ss - 32, pk + s.pk - 32);
      ok = ok && kw_decaps(&s, dev, ct) == 0 && !memcmp(dev, resp, s.ss);
    }
    printf("%-16s pk %4u B  ct %4u B  ss %2u B  20 exchanges: %s\n", s.k->name, (unsigned)s.pk, (unsigned)s.ct,
           (unsigned)s.ss, ok ? "same secret" : "FAIL");
    bad |= !ok;
    kw_free(&s);
  }
  wc_FreeRng(&rng);
  printf("%s\n", bad ? "FAIL" : "OK: wolfCrypt device side == liboqs / OpenSSL responder side");
  return bad;
}
