/* test.c - runs the Pico build of liboqs inside QEMU (see run.sh).
 * 1. SHA-3 / SHAKE known answers (FIPS 202 examples), incremental vs one-shot, 4-way vs 1-way.
 * 2. Instructions for SHAKE256 (1000 B in, 1000 B out: 8 + 8 Keccak-p[1600] permutations).
 * 3. Per algorithm: keygen / sign / verify with a deterministic RNG, instructions per operation, and
 *    a digest of pk | sk | sig. A Keccak variant is correct only if its digests equal the stock build's.
 * stdout lines: "kat,OK|FAIL", "keccak,<test>,<insns>", "alg,<name>,<keygen>,<sign>,<verify>,<ok>,<digest>" */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <oqs/sha3.h>    /* not included by oqs.h */
#include <oqs/sha3x4.h>

uint64_t insn_count(void);

static uint64_t seed;
static void rng(uint8_t *out, size_t n) {  /* splitmix64: the same bytes for every variant */
    while (n) {
        uint64_t z = (seed += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * 0x94D049BB133111EBull; z ^= z >> 31;
        size_t k = n < 8 ? n : 8;
        memcpy(out, &z, k); out += k; n -= k;
    }
}
static uint64_t fnv(uint64_t h, const uint8_t *p, size_t n) {
    while (n--) { h ^= *p++; h *= 0x100000001b3ull; }
    return h;
}
static int is(const uint8_t *b, const char *hex) {
    for (size_t i = 0; hex[2 * i]; i++) {
        unsigned v; sscanf(hex + 2 * i, "%2x", &v);
        if (b[i] != v) return 0;
    }
    return 1;
}

static const char *ALGS[] = {
    OQS_SIG_alg_ml_dsa_44, OQS_SIG_alg_ml_dsa_65, OQS_SIG_alg_falcon_512, OQS_SIG_alg_slh_dsa_pure_shake_128f,
    OQS_SIG_alg_slh_dsa_pure_sha2_128f, NULL};  /* MAYO / SNOVA left the 0.16 library for round 3 (LIBOQS_ROUND=3) */

int main(void) {
    static uint8_t big[1000], a[1000], b[1000], x[4][64], y[4][64];
    int bad = 0;
    setvbuf(stdout, NULL, _IONBF, 0);  /* each line out as it happens */
    OQS_randombytes_custom_algorithm(rng);
    for (int i = 0; i < 1000; i++) big[i] = (uint8_t)(i * 7 + 3);

    OQS_SHA3_sha3_256(a, (const uint8_t *)"abc", 3);
    bad |= !is(a, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    OQS_SHA3_shake128(a, 32, (const uint8_t *)"", 0);
    bad |= !is(a, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    OQS_SHA3_shake256(a, 32, (const uint8_t *)"", 0);
    bad |= !is(a, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    /* multi-block absorb (the fast loop) and squeeze: one-shot vs incremental in odd pieces */
    OQS_SHA3_shake256(a, 1000, big, 1000);
    OQS_SHA3_shake256_inc_ctx c;
    OQS_SHA3_shake256_inc_init(&c);
    OQS_SHA3_shake256_inc_absorb(&c, big, 1);
    OQS_SHA3_shake256_inc_absorb(&c, big + 1, 400);
    OQS_SHA3_shake256_inc_absorb(&c, big + 401, 599);
    OQS_SHA3_shake256_inc_finalize(&c);
    OQS_SHA3_shake256_inc_squeeze(b, 7, &c);
    OQS_SHA3_shake256_inc_squeeze(b + 7, 993, &c);
    OQS_SHA3_shake256_inc_ctx_release(&c);
    bad |= memcmp(a, b, 1000) != 0;
    /* 4-way (the serial x4 code calls the same Keccak) vs 1-way */
    OQS_SHA3_shake128_x4(x[0], x[1], x[2], x[3], 64, big, big + 200, big + 400, big + 600, 200);
    for (int i = 0; i < 4; i++) {
        OQS_SHA3_shake128(y[i], 64, big + 200 * i, 200);
        bad |= memcmp(x[i], y[i], 64) != 0;
    }
    printf("kat,%s\n", bad ? "FAIL" : "OK");

    uint64_t t0 = insn_count();
    OQS_SHA3_shake256(a, 1000, big, 1000);
    printf("keccak,shake256_1000in_1000out,%llu\n", (unsigned long long)(insn_count() - t0));

    for (const char **n = ALGS; *n; n++) {
        OQS_SIG *s = OQS_SIG_new(*n);
        if (!s) { printf("alg,%s,,,,unsupported,\n", *n); continue; }
        uint8_t *pk = malloc(s->length_public_key), *sk = malloc(s->length_secret_key);
        uint8_t *sig = malloc(s->length_signature), msg[32];
        size_t siglen = 0;
        memset(msg, 0x5A, sizeof msg);
        seed = 1;
        uint64_t k0 = insn_count();
        OQS_STATUS r = OQS_SIG_keypair(s, pk, sk);
        uint64_t k1 = insn_count();
        r |= OQS_SIG_sign(s, sig, &siglen, msg, sizeof msg, sk);
        uint64_t k2 = insn_count();
        r |= OQS_SIG_verify(s, msg, sizeof msg, sig, siglen, pk);
        uint64_t k3 = insn_count();
        uint64_t h = fnv(fnv(fnv(0xcbf29ce484222325ull, pk, s->length_public_key), sk, s->length_secret_key), sig, siglen);
        printf("alg,%s,%llu,%llu,%llu,%s,%016llx\n", *n, (unsigned long long)(k1 - k0), (unsigned long long)(k2 - k1),
               (unsigned long long)(k3 - k2), r == OQS_SUCCESS ? "ok" : "FAIL", (unsigned long long)h);
        bad |= r != OQS_SUCCESS;
        free(pk); free(sk); free(sig); OQS_SIG_free(s);
    }
    return bad;
}
