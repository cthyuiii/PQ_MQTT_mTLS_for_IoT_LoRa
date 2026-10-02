#!/usr/bin/env bash
# Generate the wolfSSL Arduino library that wolfssl_bench compiles against, from the same wolfSSL
# release the Pi uses (network/build_wolfssl.sh), with wolfssl_user_settings.h as its config.
# Output: $IOT_PQC_CACHE/arduino-libs/wolfssl (default ~/.cache/iot-pqc), passed to arduino-cli with
# --libraries by run_benchmarks.py. Kept out of the repo: iCloud would sync/duplicate ~150 C files.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}
SRC=${WOLFSSL_SRC:-$CACHE/wolfssl-src}
LIB="$CACHE/arduino-libs/wolfssl"
TAG=${WOLFSSL_TAG:-v5.9.4-stable}   # one release for the Mac, the Pi and the Pico (build_wolfssl.sh + make_wolfssl_lib.sh)
[ -d "$SRC" ] || git clone -q --depth 1 --branch "$TAG" https://github.com/wolfSSL/wolfssl.git "$SRC"
if [ "$(git -C "$SRC" describe --tags --exact-match 2>/dev/null)" != "$TAG" ]; then  # another release cached: switch
    git -C "$SRC" fetch -q --depth 1 origin tag "$TAG" && git -C "$SRC" checkout -q -f "$TAG" && git -C "$SRC" clean -q -fdx
fi
(cd "$SRC/IDE/ARDUINO" && rm -rf wolfssl && bash wolfssl-arduino.sh >/dev/null 2>&1) \
    || { echo "[-] wolfssl-arduino.sh failed in $SRC/IDE/ARDUINO"; exit 1; }
rm -rf "$LIB" && mkdir -p "$(dirname "$LIB")" && mv "$SRC/IDE/ARDUINO/wolfssl" "$LIB"
cp "$HERE/wolfssl_user_settings.h" "$LIB/src/user_settings.h"
echo "[+] wolfSSL Arduino library $(grep '^version=' "$LIB/library.properties" | cut -d= -f2) -> $LIB"
