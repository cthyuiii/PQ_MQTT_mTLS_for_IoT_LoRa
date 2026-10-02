// kem_wolf.h - the device side of the KEM exchange through the broker (mqtt_tls_bench's kex blocks) with wolfCrypt: a
//   key pair, whose public key goes out as an MQTT message, and decapsulation of the ciphertext that the responder
//   next to the broker (network/mqtt_tls_timer.c kem_respond: liboqs + OpenSSL) sends back. Names and byte
//   layout are that responder's: ML-KEM-512/768/1024, X25519 (the ciphertext is the responder's ephemeral share) and
//   X25519MLKEM768 as in draft-ietf-tls-ecdhe-mlkem (pk = ML-KEM key | X25519 share, ct = ML-KEM ciphertext |
//   X25519 share, secret = ML-KEM secret | X25519 secret). pico/tests/kem_host_test checks it against liboqs + OpenSSL.
#pragma once
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/curve25519.h>

struct kw_kem { const char *name; int mlkem, level; bool x25519; };  // mlkem: WC_ML_KEM_*, -1 = none; NIST category
static const kw_kem KW[] = {{"ML-KEM-512", WC_ML_KEM_512, 1, false}, {"ML-KEM-768", WC_ML_KEM_768, 3, false},
                            {"ML-KEM-1024", WC_ML_KEM_1024, 5, false}, {"X25519", -1, 0, true},
                            {"X25519MLKEM768", WC_ML_KEM_768, 3, true}};
enum { KW_N = sizeof KW / sizeof *KW, KW_MAX = 1568 + 32 };  // the largest key / ciphertext: ML-KEM-1024's

struct kw_state { const kw_kem *k; MlKemKey mk; curve25519_key xk; WC_RNG *rng; word32 pk, ct, ss; };

// sizes of this KEM's public key, ciphertext and shared secret (X25519's 32 B included); 0 = OK
static int kw_init(kw_state *s, int i, WC_RNG *rng) {
  memset(s, 0, sizeof *s);
  s->k = &KW[i]; s->rng = rng;
  if (s->k->mlkem >= 0 && (wc_MlKemKey_Init(&s->mk, s->k->mlkem, NULL, INVALID_DEVID) ||
                           wc_MlKemKey_PublicKeySize(&s->mk, &s->pk) || wc_MlKemKey_CipherTextSize(&s->mk, &s->ct) ||
                           wc_MlKemKey_SharedSecretSize(&s->mk, &s->ss)))
    return -1;
  if (s->k->x25519) { s->pk += 32; s->ct += 32; s->ss += 32; }
  return 0;
}
// a fresh key pair -> pk (s->pk bytes: the ML-KEM part first, X25519's share last)
static int kw_keypair(kw_state *s, uint8_t *pk) {
  if (s->k->mlkem >= 0 && (wc_MlKemKey_MakeKey(&s->mk, s->rng) ||
                           wc_MlKemKey_EncodePublicKey(&s->mk, pk, s->pk - (s->k->x25519 ? 32 : 0))))
    return -1;
  if (!s->k->x25519) return 0;
  word32 n = 32;
  wc_curve25519_free(&s->xk);
  return wc_curve25519_init(&s->xk) || wc_curve25519_make_key(s->rng, 32, &s->xk) ||
         wc_curve25519_export_public_ex(&s->xk, pk + s->pk - 32, &n, EC25519_LITTLE_ENDIAN) ? -1 : 0;
}
// the responder's ciphertext (s->ct bytes) -> the shared secret (s->ss bytes)
static int kw_decaps(kw_state *s, uint8_t *ss, const uint8_t *ct) {
  if (s->k->mlkem >= 0 && wc_MlKemKey_Decapsulate(&s->mk, ss, ct, s->ct - (s->k->x25519 ? 32 : 0))) return -1;
  if (!s->k->x25519) return 0;
  curve25519_key peer;
  word32 n = 32;
  int r = wc_curve25519_init(&peer) || wc_curve25519_import_public_ex(ct + s->ct - 32, 32, &peer, EC25519_LITTLE_ENDIAN) ||
          wc_curve25519_shared_secret_ex(&s->xk, &peer, ss + s->ss - 32, &n, EC25519_LITTLE_ENDIAN) ? -1 : 0;
  wc_curve25519_free(&peer);
  return r;
}
static void kw_free(kw_state *s) {
  if (s->k && s->k->mlkem >= 0) wc_MlKemKey_Free(&s->mk);
  wc_curve25519_free(&s->xk);
}
