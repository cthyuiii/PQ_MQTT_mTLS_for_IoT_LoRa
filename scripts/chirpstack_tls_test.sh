#!/usr/bin/env bash
# Can ChirpStack's own MQTT clients speak PQ TLS? (docs/pending.md step 9.) Throwaway containers of the Gateway Bridge
# (Go crypto/tls) and of ChirpStack (Rust rustls) connect to our Mosquitto (OpenSSL 3.5+) in five set-ups; our
# own client (mqtt_tls_timer, OpenSSL) is the control, it must pass all five:
#   T1 baseline   groups X25519 only           ECDSA P-256 server cert
#   T2 hybrid     groups X25519MLKEM768 only   ECDSA P-256 server cert              (the PQ key exchange)
#   T3 PQ cert    groups X25519MLKEM768 only   ML-DSA-44 server cert                (+ PQ server authentication)
#   T4 PQ mTLS    groups X25519MLKEM768 only   ML-DSA-44 server + client certs      (+ PQ client authentication)
#   T5 mixed      groups X25519MLKEM768 only   ECDSA P-256 server + client certs    (PQ key exchange, classical certs)
#   T6 PQ cert    groups X25519 only           ML-DSA-44 server cert                (PQ certs alone, classical key exchange)
#   T7 PQ mTLS    groups X25519 only           ML-DSA-44 server + client certs
#
#   bash scripts/chirpstack_tls_test.sh      # needs Docker, mosquitto, OpenSSL 3.5+ (OSSL=...), network/mqtt_tls_timer
#
# The ChirpStack container joins chirpstack-docker's network for Postgres / Redis (ChIRPSTACK_NET) but its MQTT clients
# (gateway backend + integration) point only at the test broker, so it handles no traffic. Everything it makes
# (certificates, configs, logs) goes to a temporary folder; containers and brokers are removed at the end.
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
OSSL=${OSSL:-$(command -v brew >/dev/null && echo "$(brew --prefix openssl@3)/bin/openssl" || echo openssl)}
NET=${CHIRPSTACK_NET:-chirpstack-docker_default}
T=$(mktemp -d); PIDS=()
cleanup() { docker rm -f cs-tls-gwb cs-tls-cs >/dev/null 2>&1 || true; kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
HOSTNAME_IN_DOCKER=host.docker.internal   # Docker Desktop; on Linux the containers get --add-host for it below

# --- certificates: a CA, a server and a client certificate per algorithm
cert() {  # dir, then the -newkey arguments
    local d=$T/$1; shift; mkdir -p "$d"
    "$OSSL" req -x509 -new -newkey "$@" -nodes -keyout "$d/ca.key" -out "$d/ca.crt" -days 7 -subj "/CN=IoT-PQC TLS test CA" 2>/dev/null
    for n in server client; do
        "$OSSL" req -new -newkey "$@" -nodes -keyout "$d/$n.key" -out "$d/$n.csr" -subj "/CN=$n" 2>/dev/null
        { [ $n = server ] && echo "subjectAltName=DNS:$HOSTNAME_IN_DOCKER,DNS:localhost,IP:127.0.0.1" \
                         && echo "extendedKeyUsage=serverAuth" || echo "extendedKeyUsage=clientAuth"; } > "$d/$n.ext"
        "$OSSL" x509 -req -in "$d/$n.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial -days 7 -extfile "$d/$n.ext" \
            -out "$d/$n.crt" 2>/dev/null
    done
    chmod 644 "$d"/*   # the containers read them as another user
}
cert ecdsa ec -pkeyopt ec_paramgen_curve:P-256
cert mldsa ML-DSA-44

# --- brokers: one Mosquitto per group list (OpenSSL's Groups is per process)
broker() {  # name, groups, then "port certset require-client-cert" triples
    local name=$1 groups=$2; shift 2
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n' "$groups" > "$T/$name.cnf"
    : > "$T/$name.conf"
    while [ $# -gt 0 ]; do
        printf 'listener %s 0.0.0.0\ncafile %s\ncertfile %s\nkeyfile %s\ntls_version tlsv1.3\nrequire_certificate %s\nallow_anonymous true\n' \
            "$1" "$T/$2/ca.crt" "$T/$2/server.crt" "$T/$2/server.key" "$3" >> "$T/$name.conf"
        shift 3
    done
    echo "log_dest file $T/$name.log" >> "$T/$name.conf"
    OPENSSL_CONF="$T/$name.cnf" mosquitto -c "$T/$name.conf" & PIDS+=($!)
}
broker classic X25519 18901 ecdsa false 18906 mldsa false 18907 mldsa true
broker pq X25519MLKEM768 18902 ecdsa false 18903 mldsa false 18904 mldsa true 18905 ecdsa true
sleep 1
TESTS=("T1 baseline:18901:ecdsa:" "T2 hybrid:18902:ecdsa:" "T3 PQ cert:18903:mldsa:" "T4 PQ mTLS:18904:mldsa:client"
       "T5 mixed:18905:ecdsa:client" "T6 PQ cert, X25519:18906:mldsa:" "T7 PQ mTLS, X25519:18907:mldsa:client")
ADD_HOST=(); [ "$(uname)" = Linux ] && ADD_HOST=(--add-host "$HOSTNAME_IN_DOCKER:host-gateway")

ours() {  # port set client -> PASS / FAIL: reason
    local g=X25519MLKEM768; case $1 in 18901|18906|18907) g=X25519 ;; esac
    local a=(127.0.0.1 "$1" 1 0 "$T/$2/ca.crt"); [ -n "$3" ] && a+=("$T/$2/client.crt" "$T/$2/client.key")
    local out; out=$(GROUP=$g "$R/network/mqtt_tls_timer" "${a[@]}" 2>&1) && echo PASS || echo "FAIL: ${out##*$'\n'}"
}
bridge() {
    local d=$T/gwb-$1; mkdir -p "$d"; cp "$T/$2"/{ca.crt,client.crt,client.key} "$d/"
    { echo '[integration.mqtt.auth.generic]'; echo "servers=[\"ssl://$HOSTNAME_IN_DOCKER:$1\"]"
      echo 'ca_cert="/etc/chirpstack-gateway-bridge/ca.crt"'
      [ -n "$3" ] && echo 'tls_cert="/etc/chirpstack-gateway-bridge/client.crt"' && echo 'tls_key="/etc/chirpstack-gateway-bridge/client.key"'
    } > "$d/chirpstack-gateway-bridge.toml"
    docker run -d --name cs-tls-gwb "${ADD_HOST[@]}" -v "$d":/etc/chirpstack-gateway-bridge chirpstack/chirpstack-gateway-bridge:4 >/dev/null
    sleep 6; docker logs cs-tls-gwb > "$d/log" 2>&1; docker rm -f cs-tls-gwb >/dev/null
    grep -q "connected to mqtt broker" "$d/log" && echo PASS ||
        echo "FAIL: $(grep -m1 -E 'level=(error|fatal)' "$d/log" | sed 's/" module=.*//; s/"$//; s/.*error: //')"
}
chirpstack() {
    local d=$T/cs-$1; mkdir -p "$d"; cp "$T/$2"/{ca.crt,client.crt,client.key} "$d/"
    local tls='ca_cert="/etc/chirpstack/ca.crt"'
    [ -n "$3" ] && tls+=$'\ntls_cert="/etc/chirpstack/client.crt"\ntls_key="/etc/chirpstack/client.key"'
    cat > "$d/chirpstack.toml" <<EOF
[logging]
  level="info"
[postgresql]
  dsn="postgres://chirpstack:chirpstack@postgres/chirpstack?sslmode=disable"
[redis]
  servers=["redis://redis/"]
[network]
  net_id="000000"
  enabled_regions=["as923"]
[api]
  bind="0.0.0.0:8080"
  secret="tls-test-only"
[integration]
  enabled=["mqtt"]
  [integration.mqtt]
    server="ssl://$HOSTNAME_IN_DOCKER:$1/"
    json=true
    $tls
EOF
    cat > "$d/region_as923.toml" <<EOF
[[regions]]
  id="as923"
  description="AS923 (TLS test)"
  common_name="AS923"
  [regions.gateway]
    force_gws_private=false
    [regions.gateway.backend]
      enabled="mqtt"
      [regions.gateway.backend.mqtt]
        topic_prefix="as923"
        server="ssl://$HOSTNAME_IN_DOCKER:$1"
        $tls
EOF
    docker run -d --name cs-tls-cs --network "$NET" "${ADD_HOST[@]}" -v "$d":/etc/chirpstack chirpstack/chirpstack:4 -c /etc/chirpstack >/dev/null
    sleep 8; docker logs cs-tls-cs > "$d/log" 2>&1; docker rm -f cs-tls-cs >/dev/null
    sed -i.bak 's/\x1b\[[0-9;]*m//g' "$d/log"   # no colour codes
    if grep -qiE "error|fail|panic" "$d/log"; then
        local why; why=$(grep -A1 '^Caused by' "$d/log" | sed -n 2p | sed 's/^ *//')
        [ -n "$why" ] || why=$(grep -m1 -iE 'error|fail|panic' "$d/log" | sed 's/.*error=//')
        echo "FAIL: $why"
    elif grep -qiE "connected|subscrib" "$d/log"; then echo PASS
    else echo "? (no connect line; log: $d/log)"; fi
}

echo "versions: $("$OSSL" version | cut -d' ' -f1-2), $(mosquitto -h 2>/dev/null | head -1 | cut -d' ' -f1-3)," \
     "$(docker run --rm --entrypoint chirpstack chirpstack/chirpstack:4 --version 2>/dev/null)," \
     "gateway bridge $(docker image inspect chirpstack/chirpstack-gateway-bridge:4 --format '{{index .RepoDigests 0}}' | cut -c1-60)"
printf '%-18s | %-6s | %-34s | %s\n' test "ours (OpenSSL)" "Gateway Bridge (Go)" "ChirpStack (rustls)"
for t in "${TESTS[@]}"; do
    IFS=: read -r name port set client <<< "$t"
    printf '%-18s | %-6s | %-34s | %s\n' "$name" "$(ours "$port" "$set" "$client")" "$(bridge "$port" "$set" "$client")" \
        "$(chirpstack "$port" "$set" "$client")"
done
echo "the brokers' TLS errors: $(cat "$T"/classic.log "$T"/pq.log | grep -o "error:[0-9A-F]*:SSL routines::[a-z ]*" | sort | uniq -c | tr -s ' ' | paste -sd';' -)"
[ -n "${KEEP_LOGS:-}" ] && { mkdir -p "$KEEP_LOGS"; cp -R "$T"/. "$KEEP_LOGS"/; echo "logs -> $KEEP_LOGS"; }
