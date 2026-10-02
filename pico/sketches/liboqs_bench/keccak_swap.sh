#!/usr/bin/env bash
# keccak_swap.sh IN.a MCU IMPL OUT.a - copy a Pico liboqs.a, replacing liboqs' portable Keccak-p[1600]
# (xkcp_low plain-64bits: 64-bit lanes, which a 32-bit Cortex-M emulates with pairs of instructions)
# with an XKCP implementation written for 32-bit CPUs, and SLH-DSA's separate keccak_f1600() with the
# same code (xkcp/keccak_glue.c). Everything else in liboqs is untouched.
#   MCU   cortex-m0plus | cortex-m33      (same flags as make_liboqs_lib.sh)
#   IMPL  armv6m-u1  XKCP hand-written ARMv6-M (Cortex-M0/M0+) assembler, bit-interleaved, 1 round per loop
#         armv6m-u2  the same with two rounds unrolled (XKCP's in-place ARMv6-M file does not assemble
#                    with GCC 14: an `adr` target is out of Thumb-1 range)
#         armv7m     XKCP hand-written ARMv7-M assembler (the M33 is ARMv8-M Mainline, a superset)
#         c32        XKCP portable 32-bit bit-interleaved C (no assembler)
# XKCP (https://github.com/XKCP/XKCP, CC0) is fetched once at a pinned commit into the cache.
# Correctness and instruction counts: pico/tests/qemu_liboqs/run.sh.
set -euo pipefail
IN=$1 MCU=$2 IMPL=$3 OUT=$4
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}
REV=4affab454735d54e78156880b3b44e38dcbf765c   # XKCP master, 2026-09-25
X="$CACHE/xkcp-$REV"
for f in lib/common/SnP-common.h lib/common/brg_endian.h lib/common/align.h lib/common/load-store.h \
         lib/low/common/SnP-Relaned.h lib/low/KeccakP-1600/plain-32bits-inplace/KeccakP-1600-SnP.h \
         lib/low/KeccakP-1600/plain-32bits-inplace/KeccakP-1600-inplace32BI.c \
         lib/low/KeccakP-1600/ARM/KeccakP-1600-u1-32bi-armv6m-le-gcc.s \
         lib/low/KeccakP-1600/ARM/KeccakP-1600-u2-32bi-armv6m-le-gcc.s \
         lib/low/KeccakP-1600/ARM/KeccakP-1600-inplace-32bi-armv7m-le-gcc.s; do
    [ -s "$X/$f" ] && continue
    mkdir -p "$X/$(dirname "$f")"
    curl -fsSL "https://raw.githubusercontent.com/XKCP/XKCP/$REV/$f" -o "$X/$f.part" && mv "$X/$f.part" "$X/$f"
done
GCC=""
for d in "$HOME"/Library/Arduino15/packages/rp2040/tools/pqt-gcc/*/bin \
         "$HOME"/.arduino15/packages/rp2040/tools/pqt-gcc/*/bin; do
    [ -x "$d/arm-none-eabi-gcc" ] && GCC="$d"
done
[ -n "$GCC" ] || { echo "[-] arduino-pico toolchain not found"; exit 1; }
case $MCU in
    cortex-m0plus) CPU="-mcpu=cortex-m0plus -mthumb -march=armv6-m" ;;
    cortex-m33)    CPU="-mcpu=cortex-m33 -mthumb -march=armv8-m.main+fp+dsp -mfloat-abi=softfp -mcmse" ;;
    *) echo "[-] unknown MCU $MCU"; exit 1 ;;
esac
A="$X/lib/low/KeccakP-1600/ARM"
case $MCU/$IMPL in
    cortex-m0plus/armv6m-u1) SRC="$A/KeccakP-1600-u1-32bi-armv6m-le-gcc.s" ;;
    cortex-m0plus/armv6m-u2) SRC="$A/KeccakP-1600-u2-32bi-armv6m-le-gcc.s" ;;
    cortex-m33/armv7m)       SRC="$A/KeccakP-1600-inplace-32bi-armv7m-le-gcc.s" ;;
    */c32)                   SRC="$X/lib/low/KeccakP-1600/plain-32bits-inplace/KeccakP-1600-inplace32BI.c" ;;
    *) echo "[-] $IMPL is not for $MCU"; exit 1 ;;
esac
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
"$GCC/arm-none-eabi-gcc" $CPU -O3 -ffunction-sections -fdata-sections -I"$X/lib/common" -I"$X/lib/low/common" \
    -I"$(dirname "$SRC")" -c "$SRC" -o "$T/xkcp_keccakp1600_$IMPL.o"
"$GCC/arm-none-eabi-gcc" $CPU -O3 -ffunction-sections -fdata-sections -c "$HERE/xkcp/keccak_glue.c" -o "$T/xkcp_glue.o"
cp "$IN" "$OUT"
"$GCC/arm-none-eabi-ar" d "$OUT" KeccakP-1600-opt64.c.obj   # liboqs' OQS_SHA3 Keccak
"$GCC/arm-none-eabi-ar" t "$OUT" | grep -qx sha3_f1600.c.obj && "$GCC/arm-none-eabi-ar" d "$OUT" sha3_f1600.c.obj  # SLH-DSA's own
"$GCC/arm-none-eabi-ar" rs "$OUT" "$T/xkcp_keccakp1600_$IMPL.o" "$T/xkcp_glue.o"
