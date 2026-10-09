#!/usr/bin/env bash
# Gateway side of the simulated LoRaWAN network, on the Pi: the ChirpStack Gateway Bridge in Docker. It takes the
# virtual gateway's Semtech UDP on 127.0.0.1:1700 (this Pi only, as inside a real gateway) and publishes to
# ChirpStack's MQTT broker on the other machine (README section 0.4).
#
#   PQ=~/chirpstack-pq ./scripts/setup_gateway_pi.sh <chirpstack-host-ip> [as923|eu868]    # PQ TLS (region: as923)
#   ./scripts/setup_gateway_pi.sh <chirpstack-host-ip> [as923|eu868]                       # plain MQTT to :1884
#
# PQ: a folder with ca.crt, gateway.crt, gateway.key (scripts/chirpstack_pq_setup.sh on the Mac makes them; rsync them
# here). The bridge then publishes to stunnel on 127.0.0.1:18883 (scripts/stunnel: Alpine's OpenSSL 3.5), which
# connects to <host>:8883 with TLS 1.3, X25519MLKEM768 and the gateway's ML-DSA-44 certificate: the Gateway Bridge's
# own TLS can't (finding 117). The region must match ChirpStack's (topic prefix) and virtual_gateway.py --region.
# Re-running replaces the containers. Logs: sudo docker logs -f chirpstack-gateway-bridge (and iot-pqc-stunnel).
# DRY=1: write the configs and print the docker commands instead of running them.
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
HOST=${1:?usage: [PQ=<cert folder>] $0 <chirpstack-host-ip> [as923|eu868]}
REGION=${2:-as923}
PQ=${PQ:-}
PORT=${PORT:-$([ -n "$PQ" ] && echo 8883 || echo 1884)}
case $REGION in as923|eu868) ;; *) echo "region must be as923 or eu868" >&2; exit 1 ;; esac
D="sudo docker"
run() { if [ -n "${DRY:-}" ]; then echo "+ $*"; else "$@"; fi; }

if [ -z "${DRY:-}" ]; then
    timeout 3 bash -c "</dev/tcp/$HOST/$PORT" 2>/dev/null ||
        { echo "ChirpStack's broker $HOST:$PORT is not reachable: start it there first (docker compose up -d)" >&2; exit 1; }
    command -v docker >/dev/null || { sudo apt-get update && sudo apt-get install -y docker.io; }
fi

CONF=${CONF:-$HOME/.config/chirpstack-gateway-bridge}
mkdir -p "$CONF"
SERVER="tcp://$HOST:$PORT"
if [ -n "$PQ" ]; then
    PQ=$(cd "$PQ" && pwd)
    for f in ca.crt gateway.crt gateway.key; do [ -f "$PQ/$f" ] || { echo "no $PQ/$f" >&2; exit 1; }; done
    case $HOST in *[!0-9.]*) CHECK="checkHost = $HOST" ;; *) CHECK="checkIP = $HOST" ;; esac  # the broker's name in its cert
    cat > "$CONF/stunnel.conf" <<EOF
; the Gateway Bridge -> plain MQTT on 127.0.0.1:18883 -> PQ TLS to ChirpStack's broker (setup_gateway_pi.sh)
foreground = yes
pid =
[gateway-mqtt]
client = yes
accept = 127.0.0.1:18883
connect = $HOST:$PORT
CAfile = /pq/ca.crt
cert = /pq/gateway.crt
key = /pq/gateway.key
verifyChain = yes
$CHECK
sslVersionMin = TLSv1.3
curves = X25519MLKEM768
EOF
    SERVER="tcp://127.0.0.1:18883"
fi
cat > "$CONF/chirpstack-gateway-bridge.toml" <<EOF
[backend.semtech_udp]
udp_bind="127.0.0.1:1700"

[integration.mqtt]
event_topic_template="$REGION/gateway/{{ .GatewayID }}/event/{{ .EventType }}"
state_topic_template="$REGION/gateway/{{ .GatewayID }}/state/{{ .StateType }}"
command_topic_template="$REGION/gateway/{{ .GatewayID }}/command/#"

[integration.mqtt.auth.generic]
servers=["$SERVER"]
EOF

if [ -n "$PQ" ]; then
    run $D build -q -t iot-pqc/stunnel "$R/scripts/stunnel"
    [ -n "${DRY:-}" ] || $D rm -f iot-pqc-stunnel >/dev/null 2>&1 || true
    run $D run -d --name iot-pqc-stunnel --restart unless-stopped --network host \
        -v "$PQ":/pq:ro -v "$CONF/stunnel.conf":/etc/stunnel/stunnel.conf:ro iot-pqc/stunnel
fi
[ -n "${DRY:-}" ] || $D rm -f chirpstack-gateway-bridge >/dev/null 2>&1 || true
run $D run -d --name chirpstack-gateway-bridge --restart unless-stopped --network host \
    -v "$CONF":/etc/chirpstack-gateway-bridge chirpstack/chirpstack-gateway-bridge:4
[ -z "${DRY:-}" ] || { echo "configs: $CONF"; exit 0; }
sleep 3
[ -z "$PQ" ] || $D logs iot-pqc-stunnel 2>&1 | tail -n 3
$D logs chirpstack-gateway-bridge 2>&1 | tail -n 5
$D image inspect chirpstack/chirpstack-gateway-bridge:4 --format 'image {{index .RepoDigests 0}}'
