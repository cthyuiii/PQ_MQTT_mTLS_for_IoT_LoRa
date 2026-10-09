#!/usr/bin/env bash
# Gateway side of the simulated LoRaWAN network, on the Pi: the ChirpStack Gateway Bridge in Docker. It takes the
# virtual gateway's Semtech UDP on 127.0.0.1:1700 (this Pi only, as inside a real gateway) and publishes to
# ChirpStack's MQTT broker on the other machine (docs/pending.md, step 1).
#
#   ./scripts/setup_gateway_pi.sh <chirpstack-host-ip> [as923|eu868]     # region default as923; PORT=1884 default
#
# The region must match ChirpStack's (topic prefix) and network/virtual_gateway.py --region.
# Re-running replaces the container with the new settings. Logs: sudo docker logs -f chirpstack-gateway-bridge
set -euo pipefail
HOST=${1:?usage: $0 <chirpstack-host-ip> [as923|eu868]}
REGION=${2:-as923}
PORT=${PORT:-1884}
case $REGION in as923|eu868) ;; *) echo "region must be as923 or eu868" >&2; exit 1 ;; esac

timeout 3 bash -c "</dev/tcp/$HOST/$PORT" 2>/dev/null ||
    { echo "ChirpStack's broker $HOST:$PORT is not reachable: start it there first (docker compose up -d)" >&2; exit 1; }
command -v docker >/dev/null || { sudo apt-get update && sudo apt-get install -y docker.io; }

CONF=$HOME/.config/chirpstack-gateway-bridge
mkdir -p "$CONF"
cat > "$CONF/chirpstack-gateway-bridge.toml" <<EOF
[backend.semtech_udp]
udp_bind="127.0.0.1:1700"

[integration.mqtt]
event_topic_template="$REGION/gateway/{{ .GatewayID }}/event/{{ .EventType }}"
state_topic_template="$REGION/gateway/{{ .GatewayID }}/state/{{ .StateType }}"
command_topic_template="$REGION/gateway/{{ .GatewayID }}/command/#"

[integration.mqtt.auth.generic]
servers=["tcp://$HOST:$PORT"]
EOF

sudo docker rm -f chirpstack-gateway-bridge >/dev/null 2>&1 || true
sudo docker run -d --name chirpstack-gateway-bridge --restart unless-stopped --network host \
    -v "$CONF":/etc/chirpstack-gateway-bridge chirpstack/chirpstack-gateway-bridge:4 >/dev/null
sleep 3
sudo docker logs chirpstack-gateway-bridge 2>&1 | tail -n 5
sudo docker image inspect chirpstack/chirpstack-gateway-bridge:4 --format 'image {{index .RepoDigests 0}}'
