// deploy_wolf.h - the deployment firmware's (-DMT_DEPLOY) wolfSSL / wolfCrypt pieces, with no Arduino calls, so
//   pico/tests/deploy_host_test runs this same code on the host:
//     dp_checks_ctx / dp_checks_ssl  revocation list (the CA's CRL) and the broker's name (its IP in the certificate);
//                                    certificate dates need only the build (WB_CHECKS: wolfSSL keeps its ASN time)
//     dp_ta_verify                   a trust-anchor update: "PQTA" | n (2 B, big endian) | CA DER (n B) | ML-DSA-44
//                                    signature over the 6 + n bytes before it, by the update key in the firmware
//     dp_key / dp_sign / dp_verify   ML-DSA-44 for the signed KEM exchange: the device signs with its client key and
//                                    checks the responder's signatures with the broker's server certificate's key
#pragma once
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/random.h>

// the CRL and, per connection, the expected broker name; 0 = OK
static int dp_checks_ctx(WOLFSSL_CTX *ctx, const uint8_t *crl, size_t n) {
  if (wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL) != WOLFSSL_SUCCESS) return -1;
  return wolfSSL_CTX_LoadCRLBuffer(ctx, crl, (long)n, WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS ? 0 : -2;
}
static int dp_checks_ssl(WOLFSSL *ssl, const char *name) {  // an IP literal needs its own call: the name check refuses it
  bool ip = strspn(name, "0123456789.") == strlen(name) || strchr(name, ':');  // IPv4 / IPv6
  return (ip ? wolfSSL_check_ip_address(ssl, name) : wolfSSL_check_domain_name(ssl, name)) == WOLFSSL_SUCCESS ? 0 : -1;
}

#ifndef MT_DEPLOY_CHECKS  // the full deployment firmware (ML-DSA-44, certs/DEPLOY): not the checks-only one
#include <wolfssl/wolfcrypt/dilithium.h>
typedef struct { wc_MlDsaKey k; int ready; } dp_key;
static void dp_key_free(dp_key *d) { if (d->ready) wc_MlDsaKey_Free(&d->k); d->ready = 0; }
static int dp_key_raw(dp_key *d, const uint8_t *pub, size_t n) {  // a raw ML-DSA-44 public key (the update key)
  if (wc_MlDsaKey_Init(&d->k, NULL, INVALID_DEVID)) return -1;
  d->ready = 1;
  return wc_MlDsaKey_SetParams(&d->k, WC_ML_DSA_44) || wc_MlDsaKey_ImportPubRaw(&d->k, pub, (word32)n) ? -2 : 0;
}
static int dp_key_private(dp_key *d, const uint8_t *der, size_t n) {  // the client key (PKCS#8 DER, as in mTLS)
  word32 idx = 0;
  if (wc_MlDsaKey_Init(&d->k, NULL, INVALID_DEVID)) return -1;
  d->ready = 1;
  return wc_MlDsaKey_SetParams(&d->k, WC_ML_DSA_44) || wc_MlDsaKey_PrivateKeyDecode(&d->k, der, (word32)n, &idx) ? -2 : 0;
}
// a certificate's key, after checking the certificate against the CA (the broker's server certificate)
static int dp_key_cert(dp_key *d, const uint8_t *cert, size_t n, const uint8_t *ca, size_t ca_n) {
  WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew();
  int r = !cm ? -1
        : wolfSSL_CertManagerLoadCABuffer(cm, ca, (long)ca_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ? -2
        : wolfSSL_CertManagerVerifyBuffer(cm, cert, (long)n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ? -3 : 0;
  if (cm) wolfSSL_CertManagerFree(cm);
  if (r) return r;
  DecodedCert dc;
  InitDecodedCert(&dc, cert, (word32)n, NULL);
  r = ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) ? -4 : dp_key_raw(d, dc.publicKey, dc.pubKeySize);
  FreeDecodedCert(&dc);
  return r;
}
static int dp_sign(dp_key *d, WC_RNG *rng, const uint8_t *m, size_t n, uint8_t *sig, size_t *sl) {
  word32 l = (word32)*sl;
  int r = wc_MlDsaKey_SignCtx(&d->k, NULL, 0, sig, &l, m, (word32)n, rng);  // FIPS 204, empty context (as OpenSSL)
  *sl = l;
  return r ? -1 : 0;
}
static int dp_verify(dp_key *d, const uint8_t *m, size_t n, const uint8_t *sig, size_t sl) {  // 0 = valid
  int res = 0;
  return wc_MlDsaKey_VerifyCtx(&d->k, sig, (word32)sl, NULL, 0, m, (word32)n, &res) || res != 1 ? -1 : 0;
}

// a trust-anchor update -> the CA's offset in b (6) and its length, or < 0: bad format / bad signature
static int dp_ta_verify(const uint8_t *b, size_t len, const uint8_t *upd_pub, size_t pub_n, size_t *ca_n) {
  if (len < 6 || memcmp(b, "PQTA", 4)) return -1;
  size_t n = (size_t)b[4] << 8 | b[5];
  if (6 + n >= len) return -2;
  dp_key k = {};
  int r = dp_key_raw(&k, upd_pub, pub_n) ? -3 : dp_verify(&k, b, 6 + n, b + 6 + n, len - 6 - n) ? -4 : 6;
  dp_key_free(&k);
  if (r > 0) *ca_n = n;
  return r;
}
#endif  // !MT_DEPLOY_CHECKS
