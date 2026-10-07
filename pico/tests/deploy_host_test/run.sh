#!/usr/bin/env bash
# The deployment firmware's checks (pico/sketches/mqtt_tls_bench/deploy_wolf.h) on the host, with the Pico's own wolfSSL:
# the Arduino library's sources and wolfssl_user_settings.h (-DWB_TLS -DWB_MLDSA44 -DWB_CHECKS), compiled natively.
# A local Mosquitto serves certs/DEPLOY (scripts/gen_certs.sh --deploy <IP>) on four TLS listeners; test.cpp checks
#   - a handshake with dates, the CRL and the name passes; a wrong name, revoked.crt and expired.crt are refused;
#   - the signed trust-anchor update verifies, a changed byte does not;
#   - ML-DSA-44 signatures cross between wolfCrypt (the Pico) and OpenSSL (the responder) both ways.
#   bash pico/tests/deploy_host_test/run.sh        needs mosquitto and OpenSSL 3.5+ (OSSL=...)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; R="$HERE/../../.."
C=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}; L="$C/arduino-libs/wolfssl/src"; D="$R/certs/DEPLOY"
OSSL=${OSSL:-openssl}; command -v brew >/dev/null && OSSL=${OSSL/#openssl/$(brew --prefix openssl@3)/bin/openssl}
[ -f "$L/user_settings.h" ] || bash "$R/pico/sketches/wolfssl_bench/make_wolfssl_lib.sh"
[ -f "$D/ta_update.bin" ] || { echo "[-] no $D: run scripts/gen_certs.sh --deploy <broker IP>"; exit 1; }
T=$(mktemp -d); trap 'kill $(cat "$T"/*.pid 2>/dev/null) 2>/dev/null; rm -rf "$T"' EXIT
FLAGS="-DWOLFSSL_USER_SETTINGS -DWB_TLS -DWB_MLDSA44 -DWB_CHECKS -I$L -O1 -w"
mkdir "$T/o" && printf 'cc %s -c "$1" -o "%s/o/$(echo "${1#%s/}" | tr / _).o"\n' "$FLAGS" "$T" "$L" > "$T/cc.sh"
find "$L/src" "$L/wolfcrypt/src" -name '*.c' -not -path '*/port/*' -print0 | xargs -0 -P 8 -n 1 sh "$T/cc.sh"
pem2der() { "$OSSL" "$1" -in "$2" -outform DER -out "$3"; }
pem2der x509 "$D/CA.crt" "$T/CA.der"; pem2der x509 "$D/server.crt" "$T/server.der"; pem2der crl "$D/CA.crl" "$T/CA.crl.der"
"$OSSL" pkey -in "$D/client.key" -outform DER -out "$T/client.der"
printf 'pqc deploy test' > "$T/msg"
"$OSSL" pkeyutl -sign -rawin -inkey "$D/server.key" -in "$T/msg" -out "$T/msg.server.sig"   # the responder's side
P=28890   # TLS: server.crt | revoked.crt | expired.crt
for n in server revoked expired; do
    printf 'listener %s 127.0.0.1\nallow_anonymous true\ntls_version tlsv1.3\ncafile %s/ClientCA.crt\ncertfile %s/%s.crt\nkeyfile %s/%s.key\nlog_dest none\n' \
        $P "$D" "$D" $n "$D" $n > "$T/$n.conf"
    mosquitto -c "$T/$n.conf" 2>/dev/null & echo $! > "$T/$n.pid"
    P=$((P + 1))
done
sleep 1
c++ -std=c++17 $FLAGS -I"$R/pico/sketches/mqtt_tls_bench" "$HERE/test.cpp" "$T"/o/*.o -o "$T/test"
(cd "$T" && ./test "$D" 28890 28891 28892)
"$OSSL" pkeyutl -verify -rawin -pubin -inkey <("$OSSL" pkey -in "$D/client.key" -pubout) -in "$T/msg" \
    -sigfile "$T/msg.device.sig" >/dev/null && echo "[+] OpenSSL verifies the wolfCrypt (device) signature"
