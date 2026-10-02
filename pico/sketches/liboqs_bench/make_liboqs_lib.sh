#!/usr/bin/env bash
# Cross-compile liboqs (bare-metal: OQS_EMBEDDED_BUILD) for both Pico CPUs with arduino-pico's own
# GCC, and package it as a precompiled Arduino library:
#   $IOT_PQC_CACHE/arduino-libs/liboqs/src/{cortex-m0plus,cortex-m33}/liboqs.a + headers
# liboqs has no Cortex-M code, so this is its portable C (OQS_PERMIT_UNSUPPORTED_ARCHITECTURE) -
# the same sources the Pi/Mac reach through oqs-provider and the host liboqs stage.
#   LIBOQS_KECCAK=xkcp  also writes $IOT_PQC_CACHE/arduino-libs-xkcp/liboqs: the same library with its
#                       Keccak-p[1600] replaced by XKCP's hand-written assembler (keccak_swap.sh; ARMv6-M
#                       two-round-unrolled on the RP2040, ARMv7-M on the RP2350). Checked in QEMU by
#                       pico/tests/qemu_liboqs/run.sh.
#   LIBOQS_ROUND=3      the NIST round 3 MAYO / SNOVA / MQOM / UOV sets instead: liboqs main at run_all.sh's R3_LIBOQS
#                       (the round3 stage's checkout), memory-optimised builds -> $IOT_PQC_CACHE/arduino-libs-r3/liboqs
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}
# Signatures only (Stage 1 is signature screening); every name must match liboqs' OQS_ENABLE_SIG_*.
if [ "${LIBOQS_ROUND:-}" = 3 ]; then
    SRC="$CACHE/liboqs-r3-src" LIB="$CACHE/arduino-libs-r3/liboqs" EXTRA=-DOQS_MEMOPT_BUILD=ON LIBOQS_KECCAK=""
    { [ -d "$SRC" ] || git clone -q https://github.com/open-quantum-safe/liboqs.git "$SRC"; } \
        && git -C "$SRC" checkout -q "${R3_LIBOQS:-b196b57a}"   # = run_all.sh's R3_LIBOQS
    ALGS="SIG_mayo_1;SIG_mayo_2;SIG_uov_ov_Is_pkc;SIG_uov_ov_Ip_pkc"
    ALGS="$ALGS;$(printf 'SIG_snova_SNOVA_%s;' I_K I_B I_S III_K III_B III_S V_K V_B V_S)"
    ALGS="$ALGS;$(printf 'SIG_mqom_mqom3_cat1_%s;' gf16_fast_ct gf16_short_ct gf2_shorter_ct)"
    ALGS="${ALGS%;}"
else
    SRC=${LIBOQS_SRC:-$CACHE/liboqs-src} LIB="$CACHE/arduino-libs/liboqs" EXTRA=""
    [ -d "$SRC" ] || git clone -q --depth 1 --branch "${LIBOQS_TAG:-0.16.0}" \
        https://github.com/open-quantum-safe/liboqs.git "$SRC"
    ALGS="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_falcon_512;SIG_falcon_1024"
    ALGS="$ALGS;SIG_slh_dsa_pure_sha2_128f;SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_shake_128f;SIG_slh_dsa_pure_shake_128s"
fi
GCC=""   # arduino-pico's bundled toolchain (macOS path, then Linux path)
for d in "$HOME"/Library/Arduino15/packages/rp2040/tools/pqt-gcc/*/bin \
         "$HOME"/.arduino15/packages/rp2040/tools/pqt-gcc/*/bin; do
    [ -x "$d/arm-none-eabi-gcc" ] && GCC="$d"
done
[ -n "$GCC" ] || { echo "[-] arduino-pico toolchain not found: arduino-cli core install rp2040:rp2040"; exit 1; }

STAMP="$LIB/.iot-pqc-build"   # skip when the liboqs checkout and algorithm list are unchanged
WANT="$(git -C "$SRC" rev-parse HEAD 2>/dev/null) $("$GCC/arm-none-eabi-gcc" -dumpversion) $GCC $ALGS"  # a new core / compiler rebuilds
xkcp_variant() {  # derive arduino-libs-xkcp/liboqs from the stock library
    local X="$CACHE/arduino-libs-xkcp/liboqs"
    rm -rf "$X" && mkdir -p "$(dirname "$X")" && cp -R "$LIB" "$X"
    bash "$HERE/keccak_swap.sh" "$LIB/src/cortex-m0plus/liboqs.a" cortex-m0plus armv6m-u2 "$X/src/cortex-m0plus/liboqs.a"
    bash "$HERE/keccak_swap.sh" "$LIB/src/cortex-m33/liboqs.a" cortex-m33 armv7m "$X/src/cortex-m33/liboqs.a"
    sed -i.bak 's/^sentence=.*/sentence=liboqs for RP2040 \/ RP2350 with XKCP assembler Keccak/' "$X/library.properties" && rm -f "$X/library.properties.bak"
    echo "[+] liboqs + XKCP Keccak -> $X"
}
if [ "$(cat "$STAMP" 2>/dev/null)" = "$WANT" ]; then
    echo "[+] liboqs Arduino library up to date -> $LIB"
    [ "${LIBOQS_KECCAK:-}" = xkcp ] && xkcp_variant
    exit 0
fi
rm -rf "$LIB" && mkdir -p "$LIB/src"
for MCU in cortex-m0plus cortex-m33; do
    case $MCU in   # must match arduino-pico's boards.txt toolchain options, or the link fails
        cortex-m0plus) CPU="-mcpu=cortex-m0plus -mthumb -march=armv6-m" ;;
        cortex-m33)    CPU="-mcpu=cortex-m33 -mthumb -march=armv8-m.main+fp+dsp -mfloat-abi=softfp -mcmse" ;;
    esac
    B="$CACHE/liboqs-build-$MCU${LIBOQS_ROUND:+-r$LIBOQS_ROUND}"
    rm -rf "$B"
    cmake -Wno-dev -S "$SRC" -B "$B" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_SYSTEM_NAME=Generic -DCMAKE_SYSTEM_PROCESSOR="$MCU" \
        -DCMAKE_C_COMPILER="$GCC/arm-none-eabi-gcc" -DCMAKE_AR="$GCC/arm-none-eabi-ar" \
        -DCMAKE_RANLIB="$GCC/arm-none-eabi-ranlib" -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
        -DCMAKE_C_FLAGS="$CPU -Os -ffunction-sections -fdata-sections" \
        -DOQS_EMBEDDED_BUILD=ON -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_USE_OPENSSL=OFF \
        -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="$ALGS" $EXTRA >/dev/null
    cmake --build "$B" -j"$(getconf _NPROCESSORS_ONLN)" >/dev/null
    mkdir -p "$LIB/src/$MCU" && cp "$B/lib/liboqs.a" "$LIB/src/$MCU/"
done
cp -R "$B/include/oqs" "$LIB/src/"
printf '#include <oqs/oqs.h>\n' > "$LIB/src/liboqs.h"   # Arduino resolves the library from this name
cat > "$LIB/library.properties" <<EOF
name=liboqs
version=$(grep -oE 'OQS_VERSION_TEXT "[^"]+"' "$B/include/oqs/oqsconfig.h" | cut -d'"' -f2)
author=Open Quantum Safe
maintainer=IoT-PQC (generated by pico/sketches/liboqs_bench/make_liboqs_lib.sh)
sentence=liboqs cross-compiled for RP2040 / RP2350, bare-metal
paragraph=
category=Other
url=https://openquantumsafe.org
architectures=rp2040
precompiled=true
ldflags=-loqs
EOF
echo "$WANT" > "$STAMP"
echo "[+] liboqs $(grep '^version=' "$LIB/library.properties" | cut -d= -f2) for cortex-m0plus + cortex-m33 -> $LIB"
[ "${LIBOQS_KECCAK:-}" = xkcp ] && xkcp_variant
exit 0
