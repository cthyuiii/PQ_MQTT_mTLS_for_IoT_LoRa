#!/usr/bin/env bash
# SNOVA certificates in the Pico's TLS client, on the host: the wolfSSL Arduino library (make_wolfssl_lib.sh, with its
# SNOVA patch) compiled natively per set with -DWB_TLS -DWB_SNOVA<set>, linked to this machine's liboqs main
# ($IOT_PQC_CACHE/liboqs-r3, run_all.sh's round3 stage). The round 3 broker (mqtt_bench.py --role broker, oqs-provider
# 36cafae, certs/round3) serves each set; test.cpp connects TLS and mTLS and checks a changed CA key is refused.
#   bash pico/tests/snova_tls_host_test/run.sh [SNOVA1K ...]     default: all nine sets
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$HERE/../../.." && pwd)"
C=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}; L="$C/arduino-libs/wolfssl/src"; Q="$C/liboqs-r3"
OSSL=${OSSL:-openssl}; command -v brew >/dev/null && OSSL=${OSSL/#openssl/$(brew --prefix openssl@3)/bin/openssl}
SETS=${*:-SNOVA1K SNOVA1B SNOVA1S SNOVA3K SNOVA3B SNOVA3S SNOVA5K SNOVA5B SNOVA5S}
[ -f "$L/wolfcrypt/src/wb_snova.c" ] || bash "$R/pico/sketches/wolfssl_bench/make_wolfssl_lib.sh"
[ -f "$Q/include/oqs/oqs.h" ] || { echo "[-] no $Q: ./run_all.sh round3 builds it"; exit 1; }
T=$(mktemp -d); trap 'kill $BP 2>/dev/null; wait $BP 2>/dev/null; rm -rf "$T"' EXIT
BASE=29830   # not the round 3 broker's 20830, in case --serve-broker runs here
OPENSSL_MODULES="$C/oqs-provider-r3-build/lib" python3 "$R/network/mqtt_bench.py" --role broker --mosquitto "${MOSQUITTO:-mosquitto}" \
    --base-port $BASE --certs "$R/certs/round3" --sigs $SETS --results-dir "$T" > "$T/broker.log" 2>&1 & BP=$!
port() { python3 -c "import sys; sys.path.insert(0, '$R/network'); from mqtt_bench import port_of; print(port_of($BASE, '$1', '$2'))"; }
FAIL=0
for S in $SETS; do
    echo "=== $S"
    D="$R/certs/round3/$S"; O="$T/$S"; mkdir -p "$O/o"
    der() { sed '/-----/d' "$D/$1" | base64 -d > "$O/$2"; }   # PEM -> DER (no SNOVA needed in this OpenSSL)
    der CA.crt CA.der; der client.crt client.der; der client.key client.key.der
    # one bit of the CA's public key changed: the server certificate's signature must then fail. The key's OID is the
    # certificate's second 1.3.9999.10.<n>.3; its BIT STRING (03 82 <len> 00) follows, then the key.
    python3 -c "
b = bytearray(open('$O/CA.der', 'rb').read()); o = bytes([6, 6, 43, 206, 15, 10])
i = b.find(o, b.find(o) + 1) + 8; assert b[i] == 3 and b[i + 1] == 0x82 and b[i + 4] == 0
b[i + 5 + 20] ^= 1; open('$O/CA_bad.der', 'wb').write(b)"
    FLAGS="-DWOLFSSL_USER_SETTINGS -DWB_TLS -DWB_$S -I$L -I$Q/include -O1 -w ${WB_EXTRA:-}"   # WB_EXTRA=-DDEBUG_WOLFSSL: wolfSSL's log
    printf 'cc %s -c "$1" -o "%s/o/$(echo "${1#%s/}" | tr / _).o"\n' "$FLAGS" "$O" "$L" > "$O/cc.sh"
    find "$L/src" "$L/wolfcrypt/src" -name '*.c' -not -path '*/port/*' -print0 | xargs -0 -P 8 -n 1 sh "$O/cc.sh"
    c++ -std=c++17 $FLAGS "$HERE/test.cpp" "$O"/o/*.o -L"$Q/lib" -loqs -Wl,-rpath,"$Q/lib" -o "$O/test"
    "$O/test" "$O" "$(port "$S" TLS)" "$(port "$S" mTLS)" || FAIL=1
done
[ $FAIL = 0 ] && echo "[+] every set passed" || { echo "[-] failures above; the broker's log:"; tail -20 "$T/broker.log"; exit 1; }
