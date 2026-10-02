#!/usr/bin/env bash
# Fetch the official Ascon-AEAD128 (NIST SP 800-232) C implementation; build_timer.sh compiles it into
# mqtt_tls_timer, whose pipeline carries Ascon-protected messages through the MQTT broker.
set -euo pipefail
cd "$(dirname "$0")"
REV=446347f21b209f3921c65ece70027c366cbe1693   # ascon-c main, SP 800-232 final
if [ ! -d ascon-c ]; then
    mkdir ascon-c && curl -fsSL "https://github.com/ascon/ascon-c/archive/$REV.tar.gz" \
        | tar xz --strip-components=1 -C ascon-c || { rm -rf ascon-c; exit 1; }
fi
echo "[+] ascon-c ($REV) in $(pwd)/ascon-c"
