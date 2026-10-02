// prim.h - QR-UOV round 3's primitives for the Pico: the reference prim.h's API (SHAKE128 / SHAKE256) on PQClean's
// FIPS202 instead of OpenSSL EVP. Replaces the reference prim.h / prim.c; every other file is the round 3 reference
// code unchanged. The Pico build uses PRG = shake (-DPRG_IS_AES=0): no AES-128-CTR here.
#ifndef PRIM_H
#define PRIM_H

#include <stddef.h>
#include <stdint.h>
#define shake128 fips202_shake128  // PQClean's one-shot functions share the reference's type names (unused here)
#define shake256 fips202_shake256
#include "fips202.h"
#undef shake128
#undef shake256

#if defined(PRG_IS_AES) && PRG_IS_AES
#error "the Pico build of QR-UOV uses PRG = shake: build with -DPRG_IS_AES=0"
#endif

typedef struct shake256 { shake256incctx s; int squeezing; } shake256;
typedef struct shake128 { shake128incctx s; } shake128;

// Requires (as the reference):
//   - message := update* -> digestfinal | update* -> squeeze*
//   - call order: init -> message -> (reset -> message)* -> free
void shake256_init(shake256 *ctx);
void shake256_reset(shake256 *ctx);
void shake256_update(shake256 *ctx, const uint8_t *data, size_t size);
void shake256_digestfinal(shake256 *ctx, uint8_t *dst, size_t size);
void shake256_squeeze(shake256 *ctx, uint8_t *dst, size_t size);
void shake256_free(shake256 *ctx);

// Requires: call order is init -> update* -> digestfinal -> free
void shake128_init(shake128 *ctx);
void shake128_update(shake128 *ctx, const uint8_t *data, size_t size);
void shake128_digestfinal(shake128 *ctx, uint8_t *dst, size_t size);
void shake128_free(shake128 *ctx);

#endif // PRIM_H
