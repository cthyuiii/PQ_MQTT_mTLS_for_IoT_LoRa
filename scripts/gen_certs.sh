#!/usr/bin/env bash
# Generate CA + server + client (mTLS) certs per signature algorithm under certs/<SIG>/.
# Used by run_all.sh's tls stage (tls_sweep.sh) and mqtt_bench.py (Stage 2, pipeline, round3).
#
#   ML-DSA, SLH-DSA  -> native in OpenSSL 3.5+ (default provider, no extra setup)
#   Falcon, MAYO, SNOVA -> require oqs-provider (this script auto-loads it)
#   RSA, ECDSA, EdDSA -> classical baselines
#
# Use a real OpenSSL 3.5 (NOT Apple's /usr/bin/openssl = LibreSSL). Override with:
#   OSSL=/opt/homebrew/opt/openssl@3/bin/openssl ./scripts/gen_certs.sh
# If oqs-provider lives outside the default modules dir, point to it with:
#   OPENSSL_MODULES=/path/to/dir/with/oqsprovider.dylib ./scripts/gen_certs.sh
# Only some oqs-provider sets, somewhere else (run_all.sh's round3 stage does this with the round 3 provider):
#   CERTS_DIR=certs/round3 OQS_SIGS="SNOVA1B:snova1b MAYO1:mayo1" ./scripts/gen_certs.sh
#
# Written for bash 3.2 (macOS default) - no associative arrays.
set -u
OSSL="${OSSL:-openssl}"

# --- locate + load oqs-provider -------------------------------------------
detect_oqs() {
  "$OSSL" list -providers -provider oqsprovider >/dev/null 2>&1 && return 0
  for d in "${OPENSSL_MODULES:-}" \
           "$(brew --prefix oqs-provider 2>/dev/null)/lib" \
           "$(brew --prefix oqs-provider 2>/dev/null)/lib/ossl-modules" \
           "$(brew --prefix openssl@3 2>/dev/null)/lib/ossl-modules" \
           /opt/homebrew/lib/ossl-modules /usr/local/lib/ossl-modules \
           /usr/lib/aarch64-linux-gnu/ossl-modules /usr/lib/x86_64-linux-gnu/ossl-modules; do
    [ -n "$d" ] && ls "$d"/oqsprovider.* >/dev/null 2>&1 || continue
    export OPENSSL_MODULES="$d"
    "$OSSL" list -providers -provider oqsprovider >/dev/null 2>&1 && return 0
  done
  return 1
}

if detect_oqs; then
  OQS_PROV="-provider oqsprovider -provider default"
  echo "[+] oqs-provider loaded (OPENSSL_MODULES=${OPENSSL_MODULES:-default dir})"
else
  OQS_PROV=""
  echo "[!] oqs-provider NOT found - Falcon/MAYO/SNOVA will be skipped."
  echo "    Install it:  brew install oqs-provider     (macOS)"
  echo "    or build:    https://github.com/open-quantum-safe/oqs-provider"
  echo "    then re-run (set OPENSSL_MODULES=<dir with oqsprovider.*> if needed)."
fi

ONLY_OQS=${OQS_SIGS:+1}   # a caller's OQS_SIGS = just those sets
mkdir -p "${CERTS_DIR:-certs}" && cd "${CERTS_DIR:-certs}" || exit 1
CERTS="$PWD"

# SIG_LABEL:openssl-algorithm-name . Label = certs/<label>/ dir + --sigs value.
PQC_NATIVE="
MLDSA44:ML-DSA-44
MLDSA65:ML-DSA-65
MLDSA87:ML-DSA-87
SLHDSA128F:SLH-DSA-SHA2-128f
SLHDSA128S:SLH-DSA-SHA2-128s
SLHDSA192F:SLH-DSA-SHA2-192f
"
# oqs-provider names (verify against the dump below; edit if your build differs).
OQS_SIGS="${OQS_SIGS:-
FALCON512:falcon512
FALCON1024:falcon1024
}"   # MAYO / SNOVA: their round 3 sets, certs/round3 (run_all.sh round3 stage)

# gen <label> <provider-flags> <genpkey args...>
#   -> certs/<label>/{CA,ClientCA,server,client}.{crt,key}; client.* is the mTLS device identity.
# CA signs server.crt (clients trust CA.crt), ClientCA signs client.crt (the broker trusts ClientCA.crt). OpenSSL fills
# a certificate's chain from its own trust store, so with one shared CA the broker and the OpenSSL client also sent
# the CA the peer already holds (4 KB more per direction with ML-DSA-44). With two CAs it is never in that store.
gen() {
  SIG="$1"; PROV="$2"; shift 2
  echo "[+] $SIG  ($*)"
  mkdir -p "$SIG" && cd "$SIG" || return 1
  san="subjectAltName=DNS:localhost,IP:127.0.0.1"
  for C in CA ClientCA; do
    "$OSSL" genpkey $PROV "$@" -out $C.key                                    || { cd "$CERTS"; return 1; }
    "$OSSL" req $PROV -x509 -new -key $C.key -out $C.crt -days 365 \
          -subj "/CN=PQC Test ${C/ClientCA/client CA} ($SIG)"                 || { cd "$CERTS"; return 1; }
  done
  for R in server client; do
    cn=localhost ca=CA; [ "$R" = client ] && cn=pqc-client ca=ClientCA
    "$OSSL" genpkey $PROV "$@" -out "$R.key"                                  || { cd "$CERTS"; return 1; }
    "$OSSL" req $PROV -new -key "$R.key" -out "$R.csr" -subj "/CN=$cn"        || { cd "$CERTS"; return 1; }
    "$OSSL" x509 $PROV -req -in "$R.csr" -CA $ca.crt -CAkey $ca.key -CAcreateserial \
          -out "$R.crt" -days 365 -extfile <(printf "%s" "$san")              || { cd "$CERTS"; return 1; }
  done
  rm -f ./*.csr; cd "$CERTS"
}

# --- native sigs (default provider) ---------------------------------------
[ -z "$ONLY_OQS" ] && for PAIR in $PQC_NATIVE; do
  gen "${PAIR%%:*}" "" -algorithm "${PAIR#*:}" || echo "[!] ${PAIR%%:*} failed (is this OpenSSL 3.5+?)"
done

# --- oqs-provider sigs -----------------------------------------------------
if [ -n "$OQS_PROV" ]; then
  echo "[i] signature algorithms your oqs-provider exposes (match the names above):"
  "$OSSL" list -signature-algorithms $OQS_PROV 2>/dev/null \
    | grep -iE "falcon|mayo|snova" | sed 's/^/      /'
  for PAIR in $OQS_SIGS; do
    gen "${PAIR%%:*}" "$OQS_PROV" -algorithm "${PAIR#*:}" \
      || echo "[!] ${PAIR%%:*} failed - check the name '${PAIR#*:}' against the list above."
  done
else
  echo "[i] Skipping Falcon/MAYO/SNOVA (no oqs-provider)."
fi

# --- classical baselines (RSA-2048 + ECDSA P-256 match the customer's Pico baselines) ---
[ -z "$ONLY_OQS" ] && {
gen RSA2048   "" -algorithm RSA -pkeyopt rsa_keygen_bits:2048   || echo "[!] RSA2048 failed"
gen RSA3072   "" -algorithm RSA -pkeyopt rsa_keygen_bits:3072   || echo "[!] RSA3072 failed"
gen ECDSAP256 "" -algorithm EC  -pkeyopt ec_paramgen_curve:P-256 || echo "[!] ECDSAP256 failed"
gen ED25519   "" -algorithm ED25519                              || echo "[!] ED25519 failed"
}

echo "[+] Done. Complete cert sets:"
for d in */; do s="${d%/}"; [ -s "$s/CA.crt" ] && [ -s "$s/server.crt" ] && [ -s "$s/server.key" ] && echo "    $s"; done
