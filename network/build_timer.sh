#!/usr/bin/env bash
# Build the Stage 2 / pipeline timer against OpenSSL (mqtt_tls_timer) or wolfSSL
# (mqtt_tls_timer_wolfssl), with app_aead.c for the payload protection (OpenSSL libcrypto +
# ascon-c when build_ascon.sh has fetched it).
#   bash build_timer.sh openssl      |   bash build_timer.sh wolfssl
# macOS: OPENSSL_PREFIX=$(brew --prefix openssl@3). wolfSSL: WOLFSSL_PREFIX (default: build_wolfssl.sh's).
set -euo pipefail
cd "$(dirname "$0")"
INC="" LIB=""
if [ -n "${OPENSSL_PREFIX:-}" ]; then
    INC="-I$OPENSSL_PREFIX/include"
    for d in lib lib64; do
        [ -d "$OPENSSL_PREFIX/$d" ] && LIB="$LIB -L$OPENSSL_PREFIX/$d -Wl,-rpath,$OPENSSL_PREFIX/$d"
    done
fi
D=ascon-c/crypto_aead/asconaead128/${ASCON_IMPL:-opt64}
ASCON=""
[ -f "$D/aead.c" ] && ASCON="-DHAVE_ASCON_C $D/aead.c $D/permutations.c -I$D -Iascon-c/tests"
Q=${LIBOQS_PREFIX:-${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}/liboqs-host}   # run_all.sh's liboqs 0.16 (liboqs_host)
OQS=""   # liboqs: the KEM exchange through the broker (KEM= / KEM_RESPOND=, OpenSSL build only)
if [ -f "$Q/include/oqs/oqs.h" ]; then
    OQS="-DHAVE_LIBOQS -I$Q/include"
    for d in lib lib64; do [ -d "$Q/$d" ] && OQS="$OQS -L$Q/$d -Wl,-rpath,$Q/$d"; done
    OQS="$OQS -loqs"
fi
case "${1:-openssl}" in
    openssl)
        cc -O2 mqtt_tls_timer.c app_aead.c $ASCON $INC $LIB -lssl -lcrypto -lm -o mqtt_tls_timer
        # the KEM exchange (client + responder) links liboqs: its own binary. On Linux, oqs-provider loaded into a
        # process that already holds a liboqs calls that one, not its own (round-3 MAYO / SNOVA ran round-2 code)
        [ -z "$OQS" ] || cc -O2 mqtt_tls_timer.c app_aead.c $ASCON $OQS $INC $LIB -lssl -lcrypto -lm -o mqtt_kem_timer ;;
    wolfssl)
        P=${WOLFSSL_PREFIX:-${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}/wolfssl-install}
        W="-L$P/lib -Wl,-rpath,$P/lib -lwolfssl" HS=""
        # Linux: wolfSSL linked in whole, so --wrap can time the client's crypto inside each handshake (hs_timing.c:
        # key share, its completion, verify, sign). macOS's linker has no --wrap: no such columns there.
        if [ "$(uname)" = Linux ] && [ -f "$P/lib/libwolfssl.a" ]; then
            H=../pico/sketches/mqtt_tls_bench
            W="-Wl,--whole-archive $P/lib/libwolfssl.a -Wl,--no-whole-archive -lpthread"
            HS="-DHS_TIMING -I$H $H/hs_timing.c $(sed -n 's/^WRAP(HS_[A-Z]*, \([A-Za-z0-9_]*\),.*/-Wl,--wrap=\1/p' $H/hs_timing.c)"
        fi
        cc -O2 -DUSE_WOLFSSL mqtt_tls_timer.c app_aead.c $ASCON $HS -I"$P/include" $INC $W $LIB -lcrypto -lm \
            -o mqtt_tls_timer_wolfssl || { [ -n "$HS" ] && echo "[!] handshake crypto timing did not link: without it" &&
            cc -O2 -DUSE_WOLFSSL mqtt_tls_timer.c app_aead.c $ASCON -I"$P/include" $INC -L"$P/lib" -Wl,-rpath,"$P/lib" \
               -lwolfssl $LIB -lcrypto -lm -o mqtt_tls_timer_wolfssl; } ;;
    *) echo "usage: $0 openssl|wolfssl"; exit 1 ;;
esac
echo "[+] built $(pwd)/mqtt_tls_timer$([ "${1:-openssl}" = wolfssl ] && echo _wolfssl)${ASCON:+ (with Ascon)}$([ -n "$OQS" ] && [ "${1:-openssl}" = openssl ] && echo ' + mqtt_kem_timer (liboqs KEM exchange)')"
