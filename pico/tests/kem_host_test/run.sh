#!/usr/bin/env bash
# The Pico's KEM-exchange code (pico/sketches/mqtt_tls_bench/kem_wolf.h) against liboqs + OpenSSL on the host: the same
# secret as the responder next to the broker. Needs build_wolfssl.sh's wolfSSL and run_all.sh's liboqs (the caches).
#   bash pico/tests/kem_host_test/run.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; R="$HERE/../../.."
C=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}; W=${WOLFSSL_PREFIX:-$C/wolfssl-install}; Q=${LIBOQS_PREFIX:-$C/liboqs-host}
O=${OPENSSL_PREFIX:-}; [ -z "$O" ] && command -v brew >/dev/null && O=$(brew --prefix openssl@3)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
c++ -std=c++17 -O2 "$HERE/test.cpp" -I"$R/pico/sketches/mqtt_tls_bench" -I"$W/include" -I"$Q/include" ${O:+-I$O/include} \
    -L"$W/lib" -Wl,-rpath,"$W/lib" -lwolfssl -L"$Q/lib" -Wl,-rpath,"$Q/lib" -loqs ${O:+-L$O/lib -Wl,-rpath,$O/lib} \
    -lcrypto -o "$T/test"
"$T/test"
