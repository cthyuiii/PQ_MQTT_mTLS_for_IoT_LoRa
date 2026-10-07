#!/usr/bin/env bash
# TLS 1.3 key-exchange sweep through the MQTT broker: every certificate x key exchange, TLS and mTLS. Each run is
# a full MQTT connection (TCP, TLS handshake, CONNECT / CONNACK) to the broker machine's per-certificate listeners,
# the same Mosquitto listeners as Stage 2 (./run_all.sh --serve-broker there; they accept every group below).
# The summary is the handshake part (tls_ms); Stage 2 reports the full connection for X25519MLKEM768.
# Run:  HOST=<broker IP> bash network/tls_sweep.sh        (run_all.sh: --broker IP, stage tls)
# Env:  HOST (required)  ITERS=200  TAG  MATCH (run_all.sh --algo)
#
# Writes results/tls_handshake_pure[_$TAG].csv (mode, sig, group, time stats, bytes up / down, writes / reads,
# segments, status; a combination that fails is a row with its reason) and tls_handshake_meta[_$TAG].json
# (broker, and whether it was this machine: collate_results.py counts only runs against another machine).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
TIMER="network/mqtt_tls_timer"
HOST="${HOST:?set HOST=<broker IP>: ./run_all.sh --serve-broker on another machine}"; ITERS="${ITERS:-200}"
OSSL="${OSSL:-openssl}"
# NB: do NOT name this GROUPS - that's a reserved bash variable (the user's
# group IDs; =20/staff on macOS), so assignments to it are ignored.
KEMGROUPS=$(cd network && python3 -c 'from mqtt_bench import SWEEP_GROUPS; print(*SWEEP_GROUPS)')
OUT="results/tls_handshake_pure${TAG:+_$TAG}.csv"   # run_all.sh passes TAG (mac_remote / pi_remote / ...)
META="results/tls_handshake_meta${TAG:+_$TAG}.json"

# The client verifies Falcon / MAYO / SNOVA certificates through oqs-provider: export OPENSSL_MODULES for the timer.
detect_oqs() {
  "$OSSL" list -providers -provider oqsprovider >/dev/null 2>&1 && return 0
  for d in "${OPENSSL_MODULES:-}" \
           "$(brew --prefix oqs-provider 2>/dev/null)/lib" \
           "$(brew --prefix openssl@3 2>/dev/null)/lib/ossl-modules" \
           /opt/homebrew/lib/ossl-modules /usr/local/lib/ossl-modules; do
    [ -n "$d" ] && ls "$d"/oqsprovider.* >/dev/null 2>&1 || continue
    export OPENSSL_MODULES="$d"; "$OSSL" list -providers -provider oqsprovider >/dev/null 2>&1 && return 0
  done
  return 1
}
detect_oqs && echo "[+] oqs-provider loaded (OPENSSL_MODULES=${OPENSSL_MODULES:-default dir})" \
  || echo "[i] oqs-provider not found - Falcon/MAYO/SNOVA rows will fail (native sigs still run)"

[ -x "$TIMER" ] || { echo "[-] build the timer first: bash network/build_timer.sh openssl"; exit 1; }
# the timer's per-handshake rows -> one CSV line: time stats of tls_ms; medians of the byte / socket / TCP counts
summarize() { python3 -c '
import csv, statistics as st, sys
r = list(csv.DictReader(l for l in sys.stdin if not l.startswith("#")))
if not r: sys.exit()  # handshake failed: the caller reports the error
t = sorted(float(x["tls_ms"]) for x in r); n = len(t); m = st.fmean(t)
md = lambda k: int(st.median(int(x[k]) for x in r))
tx, rx, ts, rs = md("hs_tx_B"), md("hs_rx_B"), md("tx_segs"), md("rx_segs")
print(",".join(map(str, [n, round(m, 4), round(st.median(t), 4), round(st.pstdev(t), 4), t[0], t[-1], t[int(n * .9)],
    t[int(n * .99)], round(1e3 / m, 1), tx, rx, tx + rx, md("hs_writes"), md("hs_reads"), ts, rs,
    tx + 52 * ts, rx + 52 * rs, tx + rx + 52 * (ts + rs)])))'; }

# the broker's signatures and ports (mqtt_bench.py: TLS on base+101+i, mTLS on base+1+i), with certs here
PORTS=$(cd network && python3 -c 'from mqtt_bench import SIGS_TLS, port_of
[print(s, port_of(18830, s, "TLS"), port_of(18830, s, "mTLS")) for s in SIGS_TLS]')
SIGS=()
while read -r s tport mport; do
  if [ -n "${MATCH:-}" ]; then   # run_all.sh --algo: case/punctuation-insensitive substring
    n=$(printf '%s' "$s" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9'); hit=0
    for m in $(printf '%s' "$MATCH" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9,' | tr ',' ' '); do
      case "$n" in *"$m"*) hit=1 ;; esac
    done
    [ "$hit" = 1 ] || continue
  fi
  [ -s "certs/$s/CA.crt" ] && [ -s "certs/$s/client.crt" ] && SIGS+=("$s")
done <<< "$PORTS"
[ ${#SIGS[@]} -gt 0 ] || { echo "[-] no certificate sets under certs/ (copy the broker machine's certs/, README 0.1)"; exit 1; }
echo "[+] broker: $HOST   sigs: ${SIGS[*]}"
echo "[+] groups: $KEMGROUPS   iters: $ITERS"
echo "mode,sig,group,n,mean_ms,median_ms,std_ms,min_ms,max_ms,p90_ms,p99_ms,ops_s,hs_tx_B,hs_rx_B,hs_B,writes,reads,tx_segs,rx_segs,wire_tx_B,wire_rx_B,wire_B,status" > "$OUT"
python3 -c 'import json, socket, sys, time
host = sys.argv[1]
try:
    socket.socket().bind((host, 0)); local = True   # binds only to this machine`s own addresses
except OSError:
    local = False
json.dump(dict(role="client", broker=host, broker_local=local, groups=sys.argv[2].split(), iterations=int(sys.argv[3]),
               warmup=20, started=time.strftime("%Y-%m-%dT%H:%M:%S%z")), open(sys.argv[4], "w"), indent=2)' \
  "$HOST" "$KEMGROUPS" "$ITERS" "$META"
ERR=$(mktemp); trap 'rm -f "$ERR"' EXIT

run_combo() {
  mode="$1"; sig="$2"; grp="$3"; port="$4"
  cca=""; [ "$mode" = "mTLS" ] && cca="certs/$sig/client.crt certs/$sig/client.key"
  line=$(GROUP="$grp" "$TIMER" "$HOST" "$port" "$ITERS" 20 "certs/$sig/CA.crt" $cca 2>"$ERR" | summarize)
  if [ -z "$line" ]; then   # a failure is a result: the row keeps its reason, the numbers stay empty
    why=$(tail -1 "$ERR" | tr ',' ';'); why=${why:-"no output"}
    echo "  [fail] $mode/$sig/$grp - $why"
    echo "$mode,$sig,$grp,0,,,,,,,,,,,,,,,,,,,$why" >> "$OUT"; return
  fi
  echo "$line" | awk -F, -v m="$mode/$sig/$grp" '{printf "  %-40s median %.3f ms  std %.3f  up/down %d/%d B  writes/reads %d/%d\n", m, $3, $4, $10, $11, $13, $14}'
  echo "$mode,$sig,$grp,$line,OK" >> "$OUT"
}

for mode in TLS mTLS; do
  for sig in "${SIGS[@]}"; do
    port=$(awk -v s="$sig" -v m="$mode" '$1 == s { print (m == "TLS" ? $2 : $3) }' <<< "$PORTS")
    for grp in $KEMGROUPS; do run_combo "$mode" "$sig" "$grp" "$port"; done
  done
done
echo "[+] wrote $OUT + $META"
