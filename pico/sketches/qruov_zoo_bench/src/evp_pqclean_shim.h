// evp_pqclean_shim.h - minimal OpenSSL-EVP compatibility layer backed by
// PQClean's FIPS202 (SHAKE128/256). Lets QR-UOV's qruov.c / mgf.c compile
// UNCHANGED on the RP2040 (no OpenSSL), using only the SHAKE PRG path.
//
// We declare OPENSSL_VERSION_NUMBER == 3.3 so mgf.c takes its clean
// EVP_DigestSqueeze branch and the big internal-SHA3 block is #if'd out.
// The AES-CTR cipher entry points are stubbed: with QRUOV_PRG_SHAKE defined
// they are dead code (never called), they only need to *compile*.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fips202.h"

#define OPENSSL_VERSION_NUMBER 0x30300000L
#define OPENSSL_cleanse(p, n)  memset((p), 0, (n))

#ifdef __cplusplus
extern "C" {
#endif

/* ---- message-digest (XOF) side: SHAKE128 / SHAKE256 ---- */
typedef int EVP_MD;
static inline const EVP_MD *EVP_shake128(void){ static const EVP_MD m = 128; return &m; }
static inline const EVP_MD *EVP_shake256(void){ static const EVP_MD m = 256; return &m; }

typedef struct {
  int             type;       /* 128 or 256 */
  int             finalized;
  shake128incctx  s128;
  shake256incctx  s256;
} EVP_MD_CTX;

typedef struct { int unused; } EVP_PKEY_CTX;  /* never used; for type refs */

static inline EVP_MD_CTX *EVP_MD_CTX_new(void){
  return (EVP_MD_CTX *)calloc(1, sizeof(EVP_MD_CTX));
}
static inline int EVP_DigestInit_ex(EVP_MD_CTX *c, const EVP_MD *md, void *engine){
  (void)engine; c->type = *md; c->finalized = 0;
  if (c->type == 128) shake128_inc_init(&c->s128);
  else                shake256_inc_init(&c->s256);
  return 1;
}
static inline int EVP_DigestUpdate(EVP_MD_CTX *c, const void *data, size_t n){
  if (c->type == 128) shake128_inc_absorb(&c->s128, (const uint8_t *)data, n);
  else                shake256_inc_absorb(&c->s256, (const uint8_t *)data, n);
  return 1;
}
/* finalize-once, then squeeze; safe to call repeatedly (streaming squeeze) */
static inline int EVP_DigestSqueeze(EVP_MD_CTX *c, unsigned char *out, size_t n){
  if (!c->finalized){
    if (c->type == 128) shake128_inc_finalize(&c->s128);
    else                shake256_inc_finalize(&c->s256);
    c->finalized = 1;
  }
  if (c->type == 128) shake128_inc_squeeze(out, n, &c->s128);
  else                shake256_inc_squeeze(out, n, &c->s256);
  return 1;
}
static inline int EVP_DigestFinalXOF(EVP_MD_CTX *c, unsigned char *out, size_t n){
  return EVP_DigestSqueeze(c, out, n);
}
/* POD clone: shakeNNNincctx is a flat uint64_t[] state, so struct copy suffices */
static inline int EVP_MD_CTX_copy(EVP_MD_CTX *dst, const EVP_MD_CTX *src){ *dst = *src; return 1; }
static inline int EVP_MD_CTX_copy_ex(EVP_MD_CTX *dst, const EVP_MD_CTX *src){ *dst = *src; return 1; }
static inline void EVP_MD_CTX_free(EVP_MD_CTX *c){ if (c) free(c); }

/* ---- cipher side: stubbed (dead code under QRUOV_PRG_SHAKE) ---- */
typedef int EVP_CIPHER;
static inline const EVP_CIPHER *EVP_aes_128_ctr(void){ static const EVP_CIPHER c = 1; return &c; }
static inline const EVP_CIPHER *EVP_aes_192_ctr(void){ static const EVP_CIPHER c = 2; return &c; }
static inline const EVP_CIPHER *EVP_aes_256_ctr(void){ static const EVP_CIPHER c = 3; return &c; }
typedef struct { int unused; } EVP_CIPHER_CTX;
static inline EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void){ return (EVP_CIPHER_CTX *)calloc(1, sizeof(EVP_CIPHER_CTX)); }
static inline void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c){ if (c) free(c); }
static inline int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *d, const EVP_CIPHER_CTX *s){ (void)d; (void)s; return 1; }
static inline int EVP_EncryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *ci, void *e,
                                     const unsigned char *key, const unsigned char *iv){
  (void)c; (void)ci; (void)e; (void)key; (void)iv; return 1;
}
static inline int EVP_EncryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl,
                                    const unsigned char *in, int inl){
  (void)c; (void)in; if (outl) *outl = inl; if (out && inl > 0) memset(out, 0, (size_t)inl); return 1;
}

#ifdef __cplusplus
}
#endif
