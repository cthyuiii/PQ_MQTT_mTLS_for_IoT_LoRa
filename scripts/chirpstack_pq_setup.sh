#!/usr/bin/env bash
# PQ TLS on both sides of ChirpStack (README section 0.4):
#
#   gateway → stunnel ═PQ═► ChirpStack [its Mosquitto :8883 → ChirpStack] → stunnel ═PQ═► MQTT broker ═PQ═► application
#
#   ChirpStack's Mosquitto  where gateways publish (ChirpStack reads gateways only through a broker): + listener 8883,
#                           TLS 1.3, X25519MLKEM768 only, ML-DSA-44 certificates (its own CA, configuration/pq/), a
#                           client certificate required. ChirpStack reads it inside its compose network; its plain
#                           1883 is on 127.0.0.1:1884 of this Mac only, no longer on the LAN.
#   ChirpStack → MQTT       ChirpStack's application events (its MQTT integration) go through stunnel
#                           (scripts/stunnel, Alpine's OpenSSL 3.5) to the project's PQ MQTT broker
#                           (./run_all.sh --serve-broker; its ML-DSA-44 mTLS listener is :18835), with the
#                           client certificate of APP_CERTS (default certs/MLDSA44). ChirpStack's own TLS can't (finding 117).
# All of it is docker-compose.override.yml plus new files: the compose file and its configs stay untouched, and
# `rm docker-compose.override.yml && docker compose up -d --remove-orphans` goes back. Existing certificates are kept
# (the Pi has copies); the broker's is remade if <mac-ip> isn't in it.
#
#   bash scripts/chirpstack_pq_setup.sh <mac-ip> <mqtt-broker host:port> [chirpstack-docker folder, default ~/chirpstack-docker]
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
IP=${1:?usage: $0 <the Mac LAN IP> <MQTT broker host:port, e.g. the Pi 192.168.50.132:18835> [chirpstack-docker folder]}
APP=${2:?usage: $0 <the Mac LAN IP> <MQTT broker host:port> [chirpstack-docker folder]}
CS=${3:-$HOME/chirpstack-docker}
APP_CERTS=${APP_CERTS:-$R/certs/MLDSA44}
OSSL=${OSSL:-$(command -v brew >/dev/null && echo "$(brew --prefix openssl@3)/bin/openssl" || echo openssl)}
[ -f "$CS/docker-compose.yml" ] || { echo "no $CS/docker-compose.yml (chirpstack-docker)" >&2; exit 1; }
for f in CA.crt client.crt client.key; do
    [ -f "$APP_CERTS/$f" ] || { echo "no $APP_CERTS/$f (the MQTT broker's certificate set: gen_certs.sh)" >&2; exit 1; }
done
P=$CS/configuration/pq
M=$CS/configuration/mosquitto-pq
mkdir -p "$P/stunnel" "$P/app" "$M"

cert() {  # name, then its X.509 extensions
    "$OSSL" req -new -newkey ML-DSA-44 -nodes -keyout "$P/$1.key" -out "$P/$1.csr" -subj "/CN=$1" 2>/dev/null
    printf '%s\n' "${@:2}" > "$P/$1.ext"
    "$OSSL" x509 -req -in "$P/$1.csr" -CA "$P/ca.crt" -CAkey "$P/ca.key" -CAcreateserial -days 365 -extfile "$P/$1.ext" \
        -out "$P/$1.crt" 2>/dev/null
    rm -f "$P/$1.csr" "$P/$1.ext"
    chmod 644 "$P/$1.key"  # ponytail: readable by the containers' users; a real deployment keeps keys 600, per service
    echo "[+] $1 certificate (ML-DSA-44)"
}
if [ ! -f "$P/ca.crt" ]; then
    "$OSSL" req -x509 -new -newkey ML-DSA-44 -nodes -keyout "$P/ca.key" -out "$P/ca.crt" -days 365 \
        -subj "/CN=IoT-PQC ChirpStack backend CA" 2>/dev/null
    chmod 600 "$P/ca.key"
    cert gateway "extendedKeyUsage=clientAuth"
fi
"$OSSL" x509 -in "$P/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$IP$" ||
    cert server "subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1,IP:$IP" "extendedKeyUsage=serverAuth"

# ChirpStack's Mosquitto: OpenSSL's group list = the hybrid only, so a client without ML-KEM can't fall back to X25519
printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = X25519MLKEM768\n' > "$P/openssl.cnf"
cat > "$M/mosquitto.conf" <<'EOF'
# ChirpStack's broker with a PQ listener for gateways (made by IoT-PQC scripts/chirpstack_pq_setup.sh)
listener 1883
allow_anonymous true
# TLS 1.3 with X25519MLKEM768 only (OPENSSL_CONF), ML-DSA-44 certificates, a client certificate required
listener 8883
cafile /mosquitto/pq/ca.crt
certfile /mosquitto/pq/server.crt
keyfile /mosquitto/pq/server.key
require_certificate true
tls_version tlsv1.3
EOF

# ChirpStack -> MQTT broker: stunnel with the broker set's client certificate. The broker's name is checked when its
# certificate carries the address (the benchmark sets name only localhost: then the CA alone authenticates it)
cp "$APP_CERTS/CA.crt" "$P/app/ca.crt"; cp "$APP_CERTS/client.crt" "$P/app/client.crt"; cp "$APP_CERTS/client.key" "$P/app/client.key"
chmod 644 "$P/app/client.key"
AH=${APP%:*}
CHECK="; the broker's certificate doesn't name $AH: the CA alone authenticates it"
if [ -f "$APP_CERTS/server.crt" ] && "$OSSL" x509 -in "$APP_CERTS/server.crt" -noout -ext subjectAltName 2>/dev/null |
        grep -qE "(IP Address|DNS):$AH(,|$)"; then
    case $AH in *[!0-9.]*) CHECK="checkHost = $AH" ;; *) CHECK="checkIP = $AH" ;; esac
fi
cp "$R/scripts/stunnel/Dockerfile" "$P/stunnel/Dockerfile"
cat > "$P/stunnel/stunnel.conf" <<EOF
; ChirpStack's MQTT integration -> plain on chirpstack-app-proxy:1883 (compose network) -> PQ TLS to the MQTT broker
foreground = yes
pid =
[chirpstack-integration]
client = yes
accept = 0.0.0.0:1883
connect = $APP
CAfile = /pq/app/ca.crt
cert = /pq/app/client.crt
key = /pq/app/client.key
verifyChain = yes
$CHECK
sslVersionMin = TLSv1.3
curves = X25519MLKEM768
EOF

# ChirpStack's config with its integration on the proxy (the gateway backends stay on its own Mosquitto)
awk '/^[[:space:]]*\[integration\.mqtt\][[:space:]]*$/ {s = 1}
     s == 1 && /^[[:space:]]*server=/ {sub(/server=.*/, "server=\"tcp://chirpstack-app-proxy:1883/\""); s = 2}
     {print}' "$CS/configuration/chirpstack/chirpstack.toml" > "$CS/configuration/chirpstack-pq.toml"
grep -q 'server="tcp://chirpstack-app-proxy:1883/"' "$CS/configuration/chirpstack-pq.toml" ||
    { echo "no [integration.mqtt] server= line in chirpstack.toml" >&2; exit 1; }

cat > "$CS/docker-compose.override.yml" <<'EOF'
# made by IoT-PQC scripts/chirpstack_pq_setup.sh: PQ TLS on both sides of ChirpStack. Remove this file to go back.
services:
  mosquitto:
    ports: !override
      - "127.0.0.1:1884:1883"
      - "8883:8883"
    environment:
      - OPENSSL_CONF=/mosquitto/pq/openssl.cnf
    volumes: !override
      - ./configuration/mosquitto-pq/:/mosquitto/config/
      - ./configuration/pq/:/mosquitto/pq/:ro
  chirpstack-app-proxy:
    build: ./configuration/pq/stunnel
    image: iot-pqc/stunnel
    restart: unless-stopped
    volumes:
      - ./configuration/pq/stunnel/stunnel.conf:/etc/stunnel/stunnel.conf:ro
      - ./configuration/pq/:/pq/:ro
  chirpstack:
    volumes:
      - ./configuration/chirpstack-pq.toml:/etc/chirpstack/chirpstack.toml:ro
    depends_on:
      - chirpstack-app-proxy
EOF
echo "[+] $CS/docker-compose.override.yml (MQTT broker: $APP)"
echo "next:  cd $CS && docker compose up -d --build --force-recreate --remove-orphans mosquitto chirpstack-app-proxy chirpstack"
echo "Pi:    rsync -a $P/{ca.crt,gateway.crt,gateway.key} <pi-user>@<pi-ip>:chirpstack-pq/"
