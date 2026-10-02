#if defined(PICO_VARIANT_shake_128f) || defined(PICO_VARIANT_shake_128s) || defined(PICO_VARIANT_shake_192f) || defined(PICO_VARIANT_shake_192s) || defined(PICO_VARIANT_shake_256f) || defined(PICO_VARIANT_shake_256s)  /* src/context_shake.c of slhdsa_shake_128f_bench, slhdsa_shake_128s_bench, slhdsa_shake_192f_bench, slhdsa_shake_192s_bench, slhdsa_shake_256f_bench, slhdsa_shake_256s_bench */
#include "context.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx *ctx) {
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

// in case the hash function api is heap-based.
void free_hash_function(spx_ctx *ctx) {
    (void)ctx;
}

#endif
