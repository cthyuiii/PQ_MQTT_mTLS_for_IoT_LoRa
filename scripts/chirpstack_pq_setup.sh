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
#                           (BROKER_ACL=1 ./run_all.sh --serve-broker; its ML-DSA-44 mTLS listener is :18835).
#                           ChirpStack's own TLS can't (finding 117). The proxy pins the broker's own certificate (the
#                           benchmark set names only localhost, so its CA alone would accept any certificate it issued).
#   Roles on the broker     client certificates of the broker's client CA (APP_CERTS, default certs/MLDSA44) named
#                           chirpstack (this proxy) and application (copy to the Pi), next to the devices' pqc-client;
#                           with BROKER_ACL=1 the broker's ACL gives each only its own topics.
#   ChirpStack's API secret a random one (configuration/pq/api_secret, kept across runs) instead of the compose default.
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
for f in CA.crt server.crt ClientCA.crt ClientCA.key; do
    [ -f "$APP_CERTS/$f" ] || { echo "no $APP_CERTS/$f (the MQTT broker's set, gen_certs.sh; the client CA key stays on this Mac)" >&2; exit 1; }
done
P=$CS/configuration/pq
M=$CS/configuration/mosquitto-pq
mkdir -p "$P/stunnel" "$P/app" "$M"
chmod 700 "$P"  # its keys: this user (and the containers, through Docker's file sharing) only

cert() {  # cert <folder> <CA (path without .crt / .key)> <name> <X.509 extensions...>: ML-DSA-44 key + certificate, CN=<name>
    "$OSSL" req -new -newkey ML-DSA-44 -nodes -keyout "$1/$3.key" -out "$1/$3.csr" -subj "/CN=$3" 2>/dev/null
    "$OSSL" x509 -req -in "$1/$3.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 365 \
        -extfile <(printf '%s\n' "${@:4}") -out "$1/$3.crt" 2>/dev/null
    rm -f "$1/$3.csr"
    [ "$1" != "$P" ] || chmod 644 "$1/$3.key"  # ponytail: readable by the containers' users; a real deployment keeps keys 600, per service
    echo "[+] $3 certificate (ML-DSA-44) in $1"
}
if [ ! -f "$P/ca.crt" ]; then
    "$OSSL" req -x509 -new -newkey ML-DSA-44 -nodes -keyout "$P/ca.key" -out "$P/ca.crt" -days 365 \
        -subj "/CN=IoT-PQC ChirpStack backend CA" 2>/dev/null
    chmod 600 "$P/ca.key"
    cert "$P" "$P/ca" gateway "extendedKeyUsage=clientAuth"
fi
"$OSSL" x509 -in "$P/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$IP$" ||
    cert "$P" "$P/ca" server "subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1,IP:$IP" "extendedKeyUsage=serverAuth"

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

# the broker's roles: chirpstack and application, issued by its client CA, ML-DSA-44 like the set (kept if present)
for role in chirpstack application; do
    [ -f "$APP_CERTS/$role.crt" ] || cert "$APP_CERTS" "$APP_CERTS/ClientCA" $role "extendedKeyUsage=clientAuth"
done
cp "$APP_CERTS/chirpstack.crt" "$P/app/client.crt"; cp "$APP_CERTS/chirpstack.key" "$P/app/client.key"; chmod 644 "$P/app/client.key"
cat "$APP_CERTS/CA.crt" "$APP_CERTS/server.crt" > "$P/app/broker.pem"  # the chain's CA + the broker's own certificate (pinned)
cp "$R/scripts/stunnel/Dockerfile" "$P/stunnel/Dockerfile"
cat > "$P/stunnel/stunnel.conf" <<EOF
; ChirpStack's MQTT integration -> plain on chirpstack-app-proxy:1883 (compose network) -> PQ TLS to the MQTT broker
foreground = yes
pid =
[chirpstack-integration]
client = yes
accept = 0.0.0.0:1883
connect = $APP
CAfile = /pq/app/broker.pem
cert = /pq/app/client.crt
key = /pq/app/client.key
verifyChain = yes
verifyPeer = yes
sslVersionMin = TLSv1.3
curves = X25519MLKEM768
EOF

# ChirpStack's config: its integration on the proxy (the gateway backends stay on its own Mosquitto), the downlink wait
# and the API secret. The application's reply (chirpstack_app.py --reply) goes out in the uplink's RX1 window (1 s) only
# if ChirpStack waits for it: 400 ms between handing the uplink to the integration and reading the device's queue (its
# default, 100 ms, is shorter than the reply's trip through the Pi's broker; the uplink events themselves aren't
# delayed). DOWNLINK_DELAY=100ms: ChirpStack's default again (finding 124)
DD=${DOWNLINK_DELAY:-400ms}
# ChirpStack's API secret (it signs the UI's and API's tokens): a random one, kept so a re-run doesn't log everyone out
[ -s "$P/api_secret" ] || { "$OSSL" rand -base64 32 > "$P/api_secret"; chmod 600 "$P/api_secret"; }
S=$(cat "$P/api_secret")
T=$CS/configuration/chirpstack-pq.toml
awk -v d="$DD" -v s="$S" '/^[[:space:]]*\[/ {sec = $0; gsub(/[[:space:]]/, "", sec)}
     sec == "[integration.mqtt]" && !m && /^[[:space:]]*server=/ {sub(/server=.*/, "server=\"tcp://chirpstack-app-proxy:1883/\""); m = 1}
     sec == "[api]" && !a && /^[[:space:]]*secret=/ {sub(/secret=.*/, "secret=\"" s "\""); a = 1}
     /^[[:space:]]*get_downlink_data_delay=/ {next}
     {print}
     /^[[:space:]]*\[network\][[:space:]]*$/ {print "  get_downlink_data_delay=\"" d "\""}' "$CS/configuration/chirpstack/chirpstack.toml" > "$T"
grep -q 'server="tcp://chirpstack-app-proxy:1883/"' "$T" || { echo "no [integration.mqtt] server= line in chirpstack.toml" >&2; exit 1; }
grep -q "get_downlink_data_delay=\"$DD\"" "$T" || { echo "no [network] in chirpstack.toml" >&2; exit 1; }
grep -q "secret=\"$S\"" "$T" || { echo "no [api] secret= line in chirpstack.toml" >&2; exit 1; }

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
  # the stock bridges listen on the LAN (UDP 1700, Basics Station 3001) and feed Mosquitto in plain, past the PQ
  # listener: off unless asked for (docker compose --profile stock up -d)
  chirpstack-gateway-bridge:
    profiles: [stock]
  chirpstack-gateway-bridge-basicstation:
    profiles: [stock]
EOF
echo "[+] $CS/docker-compose.override.yml (MQTT broker: $APP)"
echo "next:  cd $CS && docker compose up -d --build --force-recreate --remove-orphans mosquitto chirpstack-app-proxy chirpstack"
echo "Pi:    rsync -a $P/{ca.crt,gateway.crt,gateway.key} <pi-user>@<pi-ip>:chirpstack-pq/   (and certs/ without CA keys, README 0.1)"
echo "UI:    change the admin password (top right: admin > Change password); the API secret is new, so log in again"
