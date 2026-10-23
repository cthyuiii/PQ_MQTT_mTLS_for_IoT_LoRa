#!/usr/bin/env bash
# Gateway side of the simulated LoRaWAN network, on the Pi: the ChirpStack Gateway Bridge in Docker. It takes the
# virtual gateway's Semtech UDP on 127.0.0.1:1700 (this Pi only, as inside a real gateway) and publishes to ChirpStack's
# broker on the other machine through a Mosquitto bridge (README section 0.4):
#
#   Gateway Bridge ─TLS─► Mosquitto bridge (127.0.0.1:18883) ═PQ═► <host>:8883 (ChirpStack's door)
#
# The first hop is TLS 1.3 with X25519MLKEM768 and ECDSA P-256 certificates of a CA made here (tls/ in CONF): the Gateway
# Bridge's Go TLS takes no ML-DSA (finding 117). The bridge goes on with TLS 1.3, X25519MLKEM768 only and the gateway's
# ML-DSA-44 certificate. No plain MQTT: plain stops at the radio hop.
#
#   PQ=~/chirpstack-pq ./scripts/setup_gateway_pi.sh <chirpstack-host-ip> [as923]
#
# PQ: a folder with ca.crt, gateway.crt, gateway.key (scripts/chirpstack_pq_setup.sh on the Mac makes them; rsync them
# here). The region must match ChirpStack's (topic prefix) and virtual_gateway.py --region.
# Re-running replaces the containers. Logs: sudo docker logs -f chirpstack-gateway-bridge (and iot-pqc-gw-broker).
# DRY=1: write the configs and print the docker commands instead of running them.
set -euo pipefail
HOST=${1:?usage: PQ=<cert folder> $0 <chirpstack-host-ip> [as923]}
REGION=${2:-as923}
PQ=${PQ:?PQ=<folder with ca.crt, gateway.crt, gateway.key> (scripts/chirpstack_pq_setup.sh on the Mac makes them)}
PORT=${PORT:-8883}
OSSL=${OSSL:-openssl}
[ "$REGION" = as923 ] || { echo "region must be as923" >&2; exit 1; }
D="sudo docker"
run() { if [ -n "${DRY:-}" ]; then echo "+ $*"; else "$@"; fi; }

if [ -z "${DRY:-}" ]; then
    timeout 3 bash -c "</dev/tcp/$HOST/$PORT" 2>/dev/null ||
        { echo "ChirpStack's broker $HOST:$PORT is not reachable: start it there first (docker compose up -d)" >&2; exit 1; }
    command -v docker >/dev/null || { sudo apt-get update && sudo apt-get install -y docker.io; }
fi

CONF=${CONF:-$HOME/.config/chirpstack-gateway-bridge}
T=$CONF/tls
mkdir -p "$T"
PQ=$(cd "$PQ" && pwd)
for f in ca.crt gateway.crt gateway.key; do
    [ -f "$PQ/$f" ] || { echo "no $PQ/$f" >&2; exit 1; }
    install -m 644 "$PQ/$f" "$T/pq-$f"  # ponytail: readable by Mosquitto's user in its container; a real gateway keeps keys 600
done
cert() {  # cert <name> <X.509 extensions...>: ECDSA P-256 key + certificate from this Pi's CA, CN=<name> (kept if present)
    [ -f "$T/$1.crt" ] && return
    "$OSSL" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/$1.key" -out "$T/$1.csr" -subj "/CN=$1" 2>/dev/null
    "$OSSL" x509 -req -in "$T/$1.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial -days 365 \
        -extfile <(printf '%s\n' "${@:2}") -out "$T/$1.crt" 2>/dev/null
    rm -f "$T/$1.csr"; chmod 644 "$T/$1.key"
}
[ -f "$T/ca.crt" ] || { "$OSSL" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/ca.key" \
    -out "$T/ca.crt" -days 365 -subj "/CN=IoT-PQC gateway local CA" 2>/dev/null; chmod 600 "$T/ca.key"; }
cert broker "subjectAltName=IP:127.0.0.1" "extendedKeyUsage=serverAuth"
cert bridge "extendedKeyUsage=clientAuth"

# the bridge's OpenSSL group list = the hybrid only (the Gateway Bridge's Go TLS offers it too)
printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = X25519MLKEM768\n' > "$CONF/openssl.cnf"
cat > "$CONF/mosquitto.conf" <<EOF
# the Gateway Bridge -> TLS on 127.0.0.1:18883 -> PQ mTLS to ChirpStack's door (setup_gateway_pi.sh)
allow_anonymous false
listener 18883 127.0.0.1
cafile /tls/ca.crt
certfile /tls/broker.crt
keyfile /tls/broker.key
require_certificate true
use_identity_as_username true
tls_version tlsv1.3

connection chirpstack
address $HOST:$PORT
topic $REGION/gateway/+/event/# out 0
topic $REGION/gateway/+/state/# out 0
topic $REGION/gateway/+/command/# in 0
bridge_cafile /tls/pq-ca.crt
bridge_certfile /tls/pq-gateway.crt
bridge_keyfile /tls/pq-gateway.key
bridge_tls_version tlsv1.3
remote_clientid gateway
cleansession true
notifications false
EOF
cat > "$CONF/chirpstack-gateway-bridge.toml" <<EOF
[backend.semtech_udp]
udp_bind="127.0.0.1:1700"

[integration.mqtt]
event_topic_template="$REGION/gateway/{{ .GatewayID }}/event/{{ .EventType }}"
state_topic_template="$REGION/gateway/{{ .GatewayID }}/state/{{ .StateType }}"
command_topic_template="$REGION/gateway/{{ .GatewayID }}/command/#"

[integration.mqtt.auth.generic]
servers=["ssl://127.0.0.1:18883"]
ca_cert="/etc/chirpstack-gateway-bridge/tls/ca.crt"
tls_cert="/etc/chirpstack-gateway-bridge/tls/bridge.crt"
tls_key="/etc/chirpstack-gateway-bridge/tls/bridge.key"
EOF

[ -n "${DRY:-}" ] || $D rm -f iot-pqc-stunnel iot-pqc-gw-broker >/dev/null 2>&1 || true  # iot-pqc-stunnel: the earlier proxy
run $D run -d --name iot-pqc-gw-broker --restart unless-stopped --network host -e OPENSSL_CONF=/mosquitto/config/openssl.cnf \
    -v "$CONF/mosquitto.conf":/mosquitto/config/mosquitto.conf:ro -v "$CONF/openssl.cnf":/mosquitto/config/openssl.cnf:ro \
    -v "$T":/tls:ro eclipse-mosquitto:2
[ -n "${DRY:-}" ] || $D rm -f chirpstack-gateway-bridge >/dev/null 2>&1 || true
run $D run -d --name chirpstack-gateway-bridge --restart unless-stopped --network host \
    -v "$CONF":/etc/chirpstack-gateway-bridge chirpstack/chirpstack-gateway-bridge:4
[ -z "${DRY:-}" ] || { echo "configs: $CONF"; exit 0; }
sleep 3
$D logs iot-pqc-gw-broker 2>&1 | tail -n 3
$D logs chirpstack-gateway-bridge 2>&1 | tail -n 5
$D image inspect chirpstack/chirpstack-gateway-bridge:4 --format 'image {{index .RepoDigests 0}}'
