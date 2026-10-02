/* shake_shim.h - reimplements the tiny slice of the OpenSSL EVP API that eddsa.c uses
 *   (SHAKE256 one-shot + incremental XOF) on top of PQClean's fips202 incremental API.
 *   Ed448 only ever does: new -> fetch -> DigestInit -> DigestUpdate* -> DigestFinalXOF -> free,
 *   one finalize per context, so a thin wrapper over shake256_inc_* is sufficient. */
#ifndef SHAKE_SHIM_H
#define SHAKE_SHIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "ossl_compat.h"   /* OSSL_LIB_CTX */
#include "fips202.h"       /* shake256incctx + shake256_inc_* */

typedef struct { int tag; } EVP_MD;                       /* opaque sentinel */
typedef struct { shake256incctx ctx; int inited; } EVP_MD_CTX;

static EVP_MD shake_shim_md_ = { 1 };

static inline EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return (EVP_MD_CTX *)calloc(1, sizeof(EVP_MD_CTX));
}

static inline EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *libctx, const char *name, const char *propq)
{
    (void)libctx; (void)name; (void)propq;
    return &shake_shim_md_;                                /* always "SHAKE256" */
}

static inline int EVP_DigestInit_ex(EVP_MD_CTX *c, const EVP_MD *md, void *engine)
{
    (void)md; (void)engine;
    if (c == NULL)
        return 0;
    if (c->inited)
        shake256_inc_ctx_release(&c->ctx);
    shake256_inc_init(&c->ctx);
    c->inited = 1;
    return 1;
}

static inline int EVP_DigestUpdate(EVP_MD_CTX *c, const void *data, size_t len)
{
    if (c == NULL || !c->inited)
        return 0;
    shake256_inc_absorb(&c->ctx, (const uint8_t *)data, len);
    return 1;
}

static inline int EVP_DigestFinalXOF(EVP_MD_CTX *c, unsigned char *out, size_t outlen)
{
    if (c == NULL || !c->inited)
        return 0;
    shake256_inc_finalize(&c->ctx);
    shake256_inc_squeeze(out, outlen, &c->ctx);
    return 1;
}

static inline void EVP_MD_CTX_free(EVP_MD_CTX *c)
{
    if (c == NULL)
        return;
    if (c->inited)
        shake256_inc_ctx_release(&c->ctx);
    free(c);
}

static inline void EVP_MD_free(EVP_MD *md) { (void)md; }

#endif /* SHAKE_SHIM_H */
