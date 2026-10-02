#if defined(PICO_VARIANT_shake_128f) || defined(PICO_VARIANT_shake_128s) || defined(PICO_VARIANT_shake_192f) || defined(PICO_VARIANT_shake_192s) || defined(PICO_VARIANT_shake_256f) || defined(PICO_VARIANT_shake_256s)  /* src/thash_shake_simple.c of slhdsa_shake_128f_bench, slhdsa_shake_128s_bench, slhdsa_shake_192f_bench, slhdsa_shake_192s_bench, slhdsa_shake_256f_bench, slhdsa_shake_256s_bench */
#include <stdint.h>
#include <string.h>

#include "context.h"
#include "thash.h"

#include "params.h"
#include "utils.h"

#include "fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N + SPX_ADDR_BYTES + (inblocks * SPX_N));

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, in, inblocks * SPX_N);

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + (inblocks * SPX_N));
}

#endif
