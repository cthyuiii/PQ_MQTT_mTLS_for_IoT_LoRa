#!/usr/bin/env bash
# Build wolfSSL with TLS 1.3 + ML-KEM (X25519MLKEM768) + ML-DSA + SLH-DSA + Falcon + Ascon
# and the classical baselines, for:
#   * mqtt_tls_timer_wolfssl  (wolfSSL as the mTLS MQTT client, Stage 2)
#   * wolfcrypt/benchmark     (wolfCrypt primitive + AES/Ascon speeds, Stage 1)
#   with the deployment checks: CRLs (--enable-crl) and IP addresses in certificate names (--enable-ip-alt-name)
#
#   bash network/build_wolfssl.sh
#   WOLFSSL_EXTRA="..." bash ...   # extra ./configure flags
# Builds under $IOT_PQC_CACHE (default ~/.cache/iot-pqc): outside iCloud, and libtool breaks on the
# space in the repo path. Override with WOLFSSL_SRC / WOLFSSL_PREFIX.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}
SRC=${WOLFSSL_SRC:-$CACHE/wolfssl-src}
PREFIX=${WOLFSSL_PREFIX:-$CACHE/wolfssl-install}
TAG=${WOLFSSL_TAG:-v5.9.4-stable}   # one release for the Mac, the Pi and the Pico (build_wolfssl.sh + make_wolfssl_lib.sh)
[ -d "$SRC" ] || git clone -q --depth 1 --branch "$TAG" https://github.com/wolfSSL/wolfssl.git "$SRC"
if [ "$(git -C "$SRC" describe --tags --exact-match 2>/dev/null)" != "$TAG" ]; then  # another release cached: switch
    git -C "$SRC" fetch -q --depth 1 origin tag "$TAG" && git -C "$SRC" checkout -q -f "$TAG" && git -C "$SRC" clean -q -fdx
fi
cd "$SRC"
[ -x configure ] || ./autogen.sh
# ARMv8 asm so AES-GCM is compared fairly with OpenSSL (which uses the AES instructions).
# Pi 5 (Cortex-A76) has them; Pi 4 (A72) does not and would SIGILL -> NEON-only asm there.
ASM="" FALCON=--enable-falcon   # default: integer-emulated floating point (portable, slow signing)
if [ "$(uname -m)" = aarch64 ] || [ "$(uname -m)" = arm64 ]; then
    # native double precision, as liboqs's Falcon uses the FPU. Its 5.9.4 code leaves unused helpers, which a
    # git checkout's -Werror rejects; ac_cv_vcs_checkout=no builds it the way a release tarball does
    FALCON="--enable-falcon=double ac_cv_vcs_checkout=no"
    if [ "$(uname)" = Darwin ] || grep -qw aes /proc/cpuinfo; then ASM=--enable-armasm; else ASM=--enable-armasm=no-crypto; fi
    ASM="$ASM --enable-sp=yes --enable-sp-asm"   # wolfSSL's ARM64 P-256 / RSA code, as OpenSSL uses its own asm
fi
# Ascon and native Falcon are still behind --enable-experimental in wolfSSL 5.9.x (record this with the results).
# Falcon's TLS codepoint (0xFED7 for Falcon-512) is oqs-provider's, so the wolfSSL client can use its certificates.
CONF="--prefix=$PREFIX --enable-static --enable-experimental $ASM --enable-tls13 --enable-mlkem --enable-mldsa
    --enable-slhdsa=yes,sha2 $FALCON --enable-ascon --enable-curve25519 --enable-ed25519 --enable-ecc --enable-keygen
    --enable-sha3 --enable-shake256 --enable-crl --enable-ip-alt-name ${WOLFSSL_EXTRA:-}"
STAMP="$PREFIX/.iot-pqc-build"   # skip the rebuild when tag + configure flags are unchanged
if [ "$(cat "$STAMP" 2>/dev/null)" != "$TAG $CONF" ]; then
    ./configure -q $CONF
    make -j"$(getconf _NPROCESSORS_ONLN)"
    make install >/dev/null
    echo "$TAG $CONF" > "$STAMP"
fi

# The timer: same source as the OpenSSL build, wolfSSL for TLS (payload protection via app_aead.c)
WOLFSSL_PREFIX="$PREFIX" bash "$HERE/build_timer.sh" wolfssl
echo "[+] wolfSSL $(grep -o '"[0-9.]*"' "$PREFIX/include/wolfssl/version.h" | head -1) -> $PREFIX"
echo "[+] benchmark: $SRC/wolfcrypt/benchmark/benchmark   timer: $HERE/mqtt_tls_timer_wolfssl"
