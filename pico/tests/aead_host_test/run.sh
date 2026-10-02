#!/usr/bin/env bash
# Runs the Pico pipeline's LoRaWAN / CMAC / GCM / Ascon code (pico/sketches/mqtt_tls_bench/lora_aead.h) on the host
# (macOS or Linux) against real BearSSL (the sources arduino-pico ships) and checks every frame byte-for-byte
# against the host pipeline's implementation in network/app_aead.c. Needs: arduino-pico core, OpenSSL headers,
# network/build_ascon.sh run once (for ascon-c).    bash pico/tests/aead_host_test/run.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; R="$HERE/../../.."
CORE=""   # arduino-pico core (macOS path, then Linux path)
for d in "$HOME"/Library/Arduino15/packages/rp2040/hardware/rp2040/* "$HOME"/.arduino15/packages/rp2040/hardware/rp2040/*; do
    [ -d "$d/tools/libbearssl" ] && CORE="$d"
done
[ -n "$CORE" ] || { echo "[-] arduino-pico core not found: arduino-cli core install rp2040:rp2040"; exit 1; }
BS="$CORE/tools/libbearssl/bearssl"
A="$R/network/ascon-c/crypto_aead/asconaead128/opt64"
O=""; [ -n "${OPENSSL_PREFIX:-}" ] && O="$OPENSSL_PREFIX"; [ -z "$O" ] && command -v brew >/dev/null && O=$(brew --prefix openssl@3)
OI=${O:+-I$O/include}; OL=${O:+-L$O/lib}
B="${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}/bearssl-host-$(basename "$CORE")"   # per core version
if [ ! -f "$B/libbearssl.a" ]; then   # BearSSL from the Pico core's own sources, built once
    mkdir -p "$B/o"; i=0
    for f in $(find "$BS/src" -name '*.c'); do cc -O2 -c -I"$BS/inc" -I"$BS/src" "$f" -o "$B/o/$((i++)).o"; done
    ar rcs "$B/libbearssl.a" "$B"/o/*.o
fi
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cc -O2 -c -DHAVE_ASCON_C "$R/network/app_aead.c" -I"$A" -I"$R/network/ascon-c/tests" $OI -o "$T/app.o"
cc -O2 -c "$A/aead.c" -I"$A" -I"$R/network/ascon-c/tests" -o "$T/aead.o"
cc -O2 -c "$A/permutations.c" -I"$A" -o "$T/perm.o"
c++ -std=c++17 -O2 -x c++ "$HERE/test.cpp" -x none -I"$HERE/stub" -I"$R/pico/sketches/mqtt_tls_bench" -I"$R/network" \
    -I"$BS/inc" -I"$CORE/include" "$T/app.o" "$T/aead.o" "$T/perm.o" "$B/libbearssl.a" $OL -lcrypto -o "$T/test"
"$T/test"
