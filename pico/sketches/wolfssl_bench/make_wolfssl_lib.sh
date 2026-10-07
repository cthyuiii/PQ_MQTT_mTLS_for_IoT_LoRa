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
# wolfSSL turns certificate dates off for every ARM Arduino board ("brute-force solution": NO_ASN_TIME). arduino-pico has
# time() (NTP sets it), so -DWB_ASN_TIME (the deployment firmware) takes wolfSSL's own branch for boards with time.h.
S="$LIB/src/wolfssl/wolfcrypt/settings.h"
sed -i.bak 's/^    #if defined(INTEL_GALILEO) || defined(ESP32)$/    #if defined(INTEL_GALILEO) || defined(ESP32) || defined(WB_ASN_TIME)/' "$S" && rm -f "$S.bak"
grep -q 'defined(WB_ASN_TIME)' "$S" || { echo "[-] could not patch $S (wolfSSL changed): certificate dates stay off"; exit 1; }
# SNOVA certificates (-DWB_SNOVA<set>): Falcon-512's OID sum, OID, TLS codepoint and sizes become wolfssl_user_settings.h's
# WB_FALCON1_* (wolfSSL's own values unless WB_SNOVA), and wb_snova.c (liboqs's SNOVA) stands in for falcon.c.
W="$LIB/src/wolfssl/wolfcrypt"; C="$LIB/src/wolfcrypt/src"
perl -pi -e 's/^(    (?:CTC_FALCON_LEVEL1|FALCON_LEVEL1k)\s+= )0x7c0f3120,/${1}WB_FALCON1_SUM,/' "$W/oid_sum.h"
perl -pi -e 's/(Falcon_Level1Oid\[\] = )\{43, 206, 15, 3, 11\}/${1}{WB_FALCON1_OID}/' "$C/asn.c"
perl -pi -e 's/^(    FALCON(?:_LEVEL1)?_SA_MAJOR\s+= )0xFE,/${1}WB_FALCON1_SA_MAJOR,/; s/^(    FALCON_LEVEL1_SA_MINOR = )0xD7,/${1}WB_FALCON1_SA_MINOR,/' \
    "$LIB/src/wolfssl/internal.h"
perl -pi -e 's/^(#define FALCON_LEVEL1_KEY_SIZE\s+)1281$/${1}WB_FALCON1_KEY_SIZE/; s/^(#define FALCON_LEVEL1_SIG_SIZE\s+)666$/${1}WB_FALCON1_SIG_SIZE/;
             s/^(#define FALCON_LEVEL1_PUB_KEY_SIZE )897$/${1}WB_FALCON1_PUB_SIZE/;
             s/^(#define FALCON_MAX_PUB_KEY_SIZE )FALCON_LEVEL5_PUB_KEY_SIZE$/${1}WB_FALCON_MAX_PUB/' "$W/falcon.h"
perl -pi -e 's/^#if defined\(HAVE_FALCON\)$/#if defined(HAVE_FALCON) && !defined(WB_SNOVA)/' "$C/falcon.c"
cp "$HERE/wb_snova.c" "$C/"
N=$(cat "$W/oid_sum.h" "$C/asn.c" "$LIB/src/wolfssl/internal.h" "$W/falcon.h" "$C/falcon.c" | grep -c 'WB_FALCON\|WB_SNOVA')
[ "$N" = 12 ] || { echo "[-] SNOVA patch: $N of 12 Falcon-512 constants found (wolfSSL changed)"; exit 1; }
echo "[+] wolfSSL Arduino library $(grep '^version=' "$LIB/library.properties" | cut -d= -f2) -> $LIB"
