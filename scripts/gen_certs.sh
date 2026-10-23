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

# --- --deploy <broker IP>...: the deployment-checks sets -----------------------------------------------------------
# For mqtt_bench.py's DEPLOY listeners and the Pico's -DMT_DEPLOY firmware. The server certificate names the broker's
# IPs (the clients check the name), and each set adds what a deployed device checks:
#   CA.crl       the CA's revocation list (revokes revoked.crt; valid a year), signed with the CA's own algorithm
#   revoked.crt  expired.crt   server certificates the clients must refuse (revoked; expired 2 Jan 2025)
# DEPLOY (ML-DSA-44) also carries the trust-anchor update:
#   update.key   update.pub    the trust-anchor update key (ML-DSA-44); update.pub = its raw public key, in firmware
#   ta_update.bin              this CA as a signed trust-anchor update: "PQTA" | CA length (2 B, big endian) | CA DER |
#                              ML-DSA-44 signature over everything before it
# DEPLOY_SIGS picks the sets: DEPLOY (the default), DEPLOY_<SIG> for another certificate type, or "all" (DEPLOY and
# the other 8: the same checks, each under its own CA and CRL):
#   DEPLOY_SIGS=all ./scripts/gen_certs.sh --deploy <broker IP>...
mkcrl() {  # mkcrl <CA> <serial (hex)> <CN>: <CA>.crl revoking that one serial, signed by <CA>.key, valid a year
  printf 'R\t271231000000Z\t%s\t%s\tunknown\t/CN=%s\n' "$(date -u +%y%m%d%H%M%SZ)" "$2" "$3" > index.txt
  echo 01 > crlnumber
  printf '[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=default\ndefault_crl_days=365\n' > ca.cnf
  "$OSSL" ca $P -gencrl -config ca.cnf -keyfile "$1.key" -cert "$1.crt" -out "$1.crl" 2>/dev/null; local r=$?
  rm -f index.txt* crlnumber* ca.cnf; return $r
}
DEPLOY_ALL="DEPLOY DEPLOY_RSA2048 DEPLOY_RSA3072 DEPLOY_ECDSAP256 DEPLOY_ED25519 DEPLOY_MLDSA65 DEPLOY_MLDSA87
            DEPLOY_FALCON512 DEPLOY_FALCON1024"
gen_deploy() {  # gen_deploy <set> <provider flags> <genpkey args...>; DEPLOY_SAN = the server certificate's names
  local L=$1 P=$2; shift 2
  local ALG=("$@")
  echo "[+] $L (${ALG[*]}; server certificate for: ${DEPLOY_SAN#subjectAltName=})"
  mkdir -p "$L" && cd "$L" || return 1
  for C in CA ClientCA; do
    "$OSSL" genpkey $P "${ALG[@]}" -out $C.key                                             || return 1
    "$OSSL" req $P -x509 -new -key $C.key -out $C.crt -days 365 -subj "/CN=PQC Test ${C/ClientCA/client CA} ($L)" || return 1
  done
  issue() {  # issue <name> <CA> <CN> <x509 args...>
    "$OSSL" genpkey $P "${ALG[@]}" -out "$1.key" && "$OSSL" req $P -new -key "$1.key" -out "$1.csr" -subj "/CN=$3" &&
      "$OSSL" x509 $P -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -out "$1.crt" -extfile <(printf "%s" "$DEPLOY_SAN") "${@:4}"
  }
  issue server CA localhost -CAcreateserial -days 365                                      || return 1
  issue client ClientCA pqc-client -CAcreateserial -days 365                               || return 1
  issue revoked CA localhost -set_serial 0x5EED -days 365                                  || return 1
  issue expired CA localhost -set_serial 0x0DD -not_before 20250101000000Z -not_after 20250102000000Z || return 1
  mkcrl CA 5EED localhost                                                                  || return 1
  if [ "$L" = DEPLOY ]; then  # the trust-anchor update: always ML-DSA-44, whatever the certificates are
    "$OSSL" genpkey -algorithm ML-DSA-44 -out update.key && "$OSSL" pkey -in update.key -pubout -outform DER | tail -c 1312 > update.pub
    "$OSSL" x509 -in CA.crt -outform DER -out CA.der
    local n; n=$(wc -c < CA.der | tr -d ' ')
    { printf 'PQTA'; printf "\\$(printf %03o $((n >> 8)))\\$(printf %03o $((n & 255)))"; cat CA.der; } > ta_update.tbs
    "$OSSL" pkeyutl -sign -rawin -inkey update.key -in ta_update.tbs -out ta_update.sig    || return 1
    cat ta_update.tbs ta_update.sig > ta_update.bin
  fi
  rm -f ./*.csr ./*.tbs ./*.sig index.txt* crlnumber* ca.cnf CA.der
  "$OSSL" verify $P -crl_check -CAfile CA.crt -CRLfile CA.crl revoked.crt 2>&1 | grep -q "certificate revoked" &&
    "$OSSL" verify $P -crl_check -CAfile CA.crt -CRLfile CA.crl server.crt >/dev/null ||
    { echo "[!] $L: the CRL does not separate server.crt from revoked.crt"; return 1; }
  cd "$CERTS"
}
if [ "${1:-}" = --deploy ]; then
  shift
  [ $# -gt 0 ] || { echo "usage: [DEPLOY_SIGS=all|<sets>] $0 --deploy <broker IP>... (the address the clients connect to)"; exit 1; }
  DEPLOY_SAN="subjectAltName=DNS:localhost,IP:127.0.0.1"
  for ip in "$@"; do DEPLOY_SAN="$DEPLOY_SAN,IP:$ip"; done
  SETS=${DEPLOY_SIGS:-DEPLOY}; [ "$SETS" = all ] && SETS=$DEPLOY_ALL
  for L in $SETS; do
    P=""
    case $L in
      DEPLOY)            A="-algorithm ML-DSA-44" ;;
      DEPLOY_MLDSA65)    A="-algorithm ML-DSA-65" ;;
      DEPLOY_MLDSA87)    A="-algorithm ML-DSA-87" ;;
      DEPLOY_RSA2048)    A="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
      DEPLOY_RSA3072)    A="-algorithm RSA -pkeyopt rsa_keygen_bits:3072" ;;
      DEPLOY_ECDSAP256)  A="-algorithm EC -pkeyopt ec_paramgen_curve:P-256" ;;
      DEPLOY_ED25519)    A="-algorithm ED25519" ;;
      DEPLOY_FALCON512)  A="-algorithm falcon512";  P=$OQS_PROV ;;
      DEPLOY_FALCON1024) A="-algorithm falcon1024"; P=$OQS_PROV ;;
      *) echo "[!] unknown deployment set $L (one of: $DEPLOY_ALL)"; exit 1 ;;
    esac
    case $L in *FALCON*) [ -n "$P" ] || { echo "[!] $L skipped: needs oqs-provider"; continue; } ;; esac
    gen_deploy "$L" "$P" $A || { echo "[!] $L failed (needs OpenSSL 3.5+)"; exit 1; }
    echo "[+] Done: $CERTS/$L"
  done
  exit 0
fi

# --- --client-crl [set]...: the broker's revocation list for device certificates (BROKER_CRL=1 in mqtt_bench.py) ----
# For existing sets (default MLDSA44, the ChirpStack set-up's broker); nothing else in the set changes:
#   client_revoked.crt   a second certificate for client.key (CN pqc-client, serial 5EED): the broker must refuse it
#   ClientCA.crl         the client CA's CRL revoking it, valid a year; client, chirpstack and application still pass
if [ "${1:-}" = --client-crl ]; then
  shift
  for L in "${@:-MLDSA44}"; do
    P=""; case $L in FALCON*|*MAYO*|*SNOVA*) P=$OQS_PROV ;; esac
    ( cd "$L" 2>/dev/null && [ -f ClientCA.key ] || { echo "[!] $L: no $CERTS/$L/ClientCA.key (it stays on the Mac)"; exit 1; }
      "$OSSL" req $P -new -key client.key -subj /CN=pqc-client -out r.csr &&
        "$OSSL" x509 $P -req -in r.csr -CA ClientCA.crt -CAkey ClientCA.key -set_serial 0x5EED -days 365 \
          -extfile <(echo extendedKeyUsage=clientAuth) -out client_revoked.crt 2>/dev/null && rm r.csr &&
        mkcrl ClientCA 5EED pqc-client || exit 1
      "$OSSL" verify $P -crl_check -CAfile ClientCA.crt -CRLfile ClientCA.crl client_revoked.crt 2>&1 | grep -q "certificate revoked" ||
        { echo "[!] $L: client_revoked.crt is not refused"; exit 1; }
      for c in client chirpstack application; do
        [ -f $c.crt ] || continue
        "$OSSL" verify $P -crl_check -CAfile ClientCA.crt -CRLfile ClientCA.crl $c.crt >/dev/null || { echo "[!] $L: $c.crt refused"; exit 1; }
      done
      echo "[+] $L: ClientCA.crl revokes client_revoked.crt; the other client certificates pass" ) || exit 1
  done
  exit 0
fi

# --- --server-names <set> <name>...: the set's server.crt again, naming the broker the way its clients reach it ------
# For clients that check the name (rustls in our ChirpStack build). The set's CA and server.key stay, so the devices'
# CA.crt and every client certificate stay valid. Names in subjectAltName form, e.g. IP:192.168.50.132.
if [ "${1:-}" = --server-names ]; then
  L=${2:-}; shift 2 2>/dev/null
  [ -n "$L" ] && [ $# -gt 0 ] || { echo "usage: $0 --server-names <set> IP:<address>|DNS:<name>..."; exit 1; }
  P=""; case $L in FALCON*|*MAYO*|*SNOVA*) P=$OQS_PROV ;; esac
  ( cd "$L" 2>/dev/null && [ -f CA.key ] || { echo "[!] $L: no $CERTS/$L/CA.key (it stays on the Mac)"; exit 1; }
    san="subjectAltName=DNS:localhost,IP:127.0.0.1$(printf ',%s' "$@")"
    "$OSSL" req $P -new -key server.key -subj /CN=localhost -out s.csr &&
      "$OSSL" x509 $P -req -in s.csr -CA CA.crt -CAkey CA.key -CAcreateserial -days 365 -extfile <(echo "$san") \
        -out server.crt 2>/dev/null && rm s.csr && "$OSSL" verify $P -CAfile CA.crt server.crt >/dev/null || exit 1
    echo "[+] $L: server.crt now names $("$OSSL" x509 -in server.crt -noout -ext subjectAltName | tail -1 | xargs)" ) || exit 1
  exit 0
fi

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
