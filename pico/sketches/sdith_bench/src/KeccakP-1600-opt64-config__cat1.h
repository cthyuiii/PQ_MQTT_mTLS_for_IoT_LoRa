/*
This file defines some parameters of the implementation in the parent directory.
*/

#define KeccakP1600_implementation_config "all rounds unrolled"
#define KeccakP1600_fullUnrolling

/* RP2040/Cortex-M0+: byte-wise fallback for unaligned data in opt64. */
#define NO_MISALIGNED_ACCESSES
