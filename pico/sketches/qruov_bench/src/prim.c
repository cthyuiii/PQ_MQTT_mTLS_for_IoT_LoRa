// prim.c - see prim.h: SHAKE128 / SHAKE256 for QR-UOV round 3 on PQClean's incremental FIPS202.
#include "prim.h"

void shake256_init(shake256 *ctx) { shake256_inc_init(&ctx->s); ctx->squeezing = 0; }
void shake256_reset(shake256 *ctx) { shake256_inc_ctx_release(&ctx->s); shake256_init(ctx); }
void shake256_update(shake256 *ctx, const uint8_t *data, size_t size) { shake256_inc_absorb(&ctx->s, data, size); }
void shake256_digestfinal(shake256 *ctx, uint8_t *dst, size_t size) {
    shake256_inc_finalize(&ctx->s);
    shake256_inc_squeeze(dst, size, &ctx->s);
}
void shake256_squeeze(shake256 *ctx, uint8_t *dst, size_t size) {  // the first squeeze finalizes, later ones continue
    if (!ctx->squeezing) { shake256_inc_finalize(&ctx->s); ctx->squeezing = 1; }
    shake256_inc_squeeze(dst, size, &ctx->s);
}
void shake256_free(shake256 *ctx) { shake256_inc_ctx_release(&ctx->s); }

void shake128_init(shake128 *ctx) { shake128_inc_init(&ctx->s); }
void shake128_update(shake128 *ctx, const uint8_t *data, size_t size) { shake128_inc_absorb(&ctx->s, data, size); }
void shake128_digestfinal(shake128 *ctx, uint8_t *dst, size_t size) {
    shake128_inc_finalize(&ctx->s);
    shake128_inc_squeeze(dst, size, &ctx->s);
}
void shake128_free(shake128 *ctx) { shake128_inc_ctx_release(&ctx->s); }
