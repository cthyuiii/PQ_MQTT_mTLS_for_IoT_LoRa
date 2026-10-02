/* keccak_glue.c - linked by keccak_swap.sh next to an XKCP Keccak-p[1600].
 * 1. The two SnP entry points liboqs calls that XKCP's 32-bit implementations leave out: liboqs' SHA-3
 *    layer (src/common/sha3/xkcp_sha3.c) absorbs whole blocks through KeccakF1600_FastLoop_Absorb, and
 *    its serial 4-way code calls KeccakP1600_StaticInitialize as a function (XKCP makes both macros).
 * 2. keccak_f1600(): liboqs' SLH-DSA (slh-dsa-c, sha3_f1600.c) has its own 64-bit-lane permutation and
 *    never reaches OQS_SHA3; this replaces it with XKCP's, converting to and from XKCP's bit-interleaved
 *    state around each call. */
#include <stddef.h>
#include <stdint.h>

void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_Permute_24rounds(void *state);
void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_ExtractBytes(const void *state, unsigned char *data, unsigned int offset, unsigned int length);

/* absorb as many full rate-sized blocks as dataByteLen holds; returns the bytes consumed */
size_t KeccakF1600_FastLoop_Absorb(void *state, unsigned int laneCount, const unsigned char *data,
                                   size_t dataByteLen) {
    size_t block = (size_t)laneCount * 8, done = 0;
    while (dataByteLen - done >= block) {
        KeccakP1600_AddBytes(state, data + done, 0, (unsigned int)block);
        KeccakP1600_Permute_24rounds(state);
        done += block;
    }
    return done;
}

__attribute__((weak)) void KeccakP1600_StaticInitialize(void) {}  /* the assembler may define it */

/* slh-dsa-c's lanes are little-endian uint64_t, i.e. Keccak's byte order, so bytes in, bytes out */
void keccak_f1600(uint64_t x[25]) {
    uint32_t s[50];  /* XKCP's 32-bit bit-interleaved state */
    KeccakP1600_OverwriteBytes(s, (const unsigned char *)x, 0, 200);
    KeccakP1600_Permute_24rounds(s);
    KeccakP1600_ExtractBytes(s, (unsigned char *)x, 0, 200);
}
