#!/usr/bin/env bash
# TLS on every MQTT hop around ChirpStack, PQ on every hop between machines (README section 0.4):
#
#   gateway ═PQ═► mosquitto-pq ─TLS─► ChirpStack's Mosquitto ─TLS─► ChirpStack, and back:
#   ChirpStack ─TLS─► its Mosquitto ─TLS─► mosquitto-pq ═PQ═► MQTT broker ═PQ═► application
#
#   mosquitto-pq            the door on the LAN: listener 8883, TLS 1.3, X25519MLKEM768 only (OPENSSL_CONF), ML-DSA-44
#                           certificates (its own CA, configuration/pq/), a client certificate required, an ACL per
#                           certificate name (gateways: their gateway topics only). It bridges the gateway topics and
#                           ChirpStack's application topics to ChirpStack's Mosquitto, and the application topics on
#                           to the project's PQ MQTT broker (BROKER_ACL=1 ./run_all.sh --serve-broker, ML-DSA-44 mTLS
#                           :18835) as `chirpstack`. That broker's certificate names only localhost, so the bridge
#                           checks its set's CA, which signs no other certificate (gen_certs.sh), not the name.
#   ChirpStack's Mosquitto  TLS only (listener 8884, no port outside the compose network): ChirpStack's TLS (rustls with
#                           ring) has no ML-KEM and no ML-DSA (finding 117), so this hop uses ECDSA P-256 certificates
#                           of a second CA (configuration/pq/local/) and X25519. It never leaves the Mac.
#   Roles on the broker     client certificates of the broker's client CA (APP_CERTS, default certs/MLDSA44) named
#                           chirpstack (the bridge) and application (copy to the Pi), next to the devices' pqc-client;
#                           with BROKER_ACL=1 the broker's ACL gives each only its own topics.
#   ChirpStack's API secret a random one (configuration/pq/api_secret, kept across runs) instead of the compose default.
#   CHIRPSTACK_IMAGE=iot-pqc/chirpstack:4.19.2-pq: our build (scripts/chirpstack/Dockerfile: rustls on aws-lc-rs) does
#                           X25519MLKEM768 and ML-DSA-44 itself (finding 128), so its integration connects straight to
#                           the MQTT broker as `chirpstack` and the door no longer bridges to it. rustls checks the
#                           broker's name: its server.crt must name <mqtt-broker host> (gen_certs.sh --server-names).
#   GATEWAY_IMAGE=iot-pqc/gateway-bridge:4.1.2-go1.27 (with CHIRPSTACK_IMAGE): the Gateway Bridge built with Go 1.27
#                           (scripts/gateway-bridge, finding 129) runs here too, as on a gateway that shares its machine
#                           with ChirpStack. It takes the packet forwarder's UDP on 127.0.0.1:1700 only and publishes to
#                           the MQTT broker as `gateway` (ML-DSA-44 mTLS; Go reads the key only in seed-only form), and
#                           ChirpStack's gateway backend connects to that broker too: the gateway, ChirpStack and the
#                           application all on the one PQ broker. The door and ChirpStack's own Mosquitto go unused.
# All of it is docker-compose.override.yml plus new files: the compose file and its configs stay untouched, and
# `rm docker-compose.override.yml && docker compose up -d --remove-orphans` goes back. Existing certificates are kept
# (the Pi has copies); the door's is remade if <mac-ip> isn't in it.
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
for f in CA.crt ClientCA.crt ClientCA.key; do
    [ -f "$APP_CERTS/$f" ] || { echo "no $APP_CERTS/$f (the MQTT broker's set, gen_certs.sh; the client CA key stays on this Mac)" >&2; exit 1; }
done
IMG=${CHIRPSTACK_IMAGE:-}
GW=${GATEWAY_IMAGE:-}
[ -z "$GW" ] || [ -n "$IMG" ] ||
    { echo "GATEWAY_IMAGE needs CHIRPSTACK_IMAGE: the stock ChirpStack can't reach the MQTT broker (no ML-DSA)" >&2; exit 1; }
if [ -n "$IMG" ]; then
    H=${APP%:*}; case $H in *[!0-9.]*) N="DNS:$H" ;; *) N="IP Address:$H" ;; esac
    "$OSSL" x509 -in "$APP_CERTS/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "$N\(,\|$\)" ||
        { echo "$APP_CERTS/server.crt doesn't name $H: gen_certs.sh --server-names ${APP_CERTS##*/} ${N/IP Address/IP}" >&2; exit 1; }
fi
P=$CS/configuration/pq
L=$P/local
M=$CS/configuration/mosquitto-pq
ML=$CS/configuration/mosquitto-local
CC=$CS/configuration/chirpstack-pq
mkdir -p "$P/app" "$L" "$M" "$ML" "$CC"
chmod 700 "$P"  # its keys: this user (and the containers, through Docker's file sharing) only

ALG=ML-DSA-44
cert() {  # cert <folder> <CA (path without .crt / .key)> <name> <X.509 extensions...>: $ALG key + certificate, CN=<name>
    "$OSSL" req -new -newkey $ALG -nodes -keyout "$1/$3.key" -out "$1/$3.csr" -subj "/CN=$3" 2>/dev/null
    "$OSSL" x509 -req -in "$1/$3.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 365 \
        -extfile <(printf '%s\n' "${@:4}") -out "$1/$3.crt" 2>/dev/null
    rm -f "$1/$3.csr"
    [[ $1 != "$P"* ]] || chmod 644 "$1/$3.key"  # ponytail: readable by the containers' users; a real deployment keeps keys 600, per service
    echo "[+] $3 certificate (${ALG%% *}) in $1"
}
if [ ! -f "$P/ca.crt" ]; then
    "$OSSL" req -x509 -new -newkey ML-DSA-44 -nodes -keyout "$P/ca.key" -out "$P/ca.crt" -days 365 \
        -subj "/CN=IoT-PQC ChirpStack backend CA" 2>/dev/null
    chmod 600 "$P/ca.key"
    cert "$P" "$P/ca" gateway "extendedKeyUsage=clientAuth"
fi
"$OSSL" x509 -in "$P/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$IP$" ||
    cert "$P" "$P/ca" server "subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1,IP:$IP" "extendedKeyUsage=serverAuth"
# the hops inside the Mac: ECDSA P-256 (ChirpStack's TLS takes nothing else of these)
ALG="ec -pkeyopt ec_paramgen_curve:P-256"
if [ ! -f "$L/ca.crt" ]; then
    "$OSSL" req -x509 -new -newkey $ALG -nodes -keyout "$L/ca.key" -out "$L/ca.crt" -days 365 \
        -subj "/CN=IoT-PQC ChirpStack local CA" 2>/dev/null
    chmod 600 "$L/ca.key"
fi
[ -f "$L/mosquitto.crt" ] || cert "$L" "$L/ca" mosquitto "subjectAltName=DNS:mosquitto" "extendedKeyUsage=serverAuth"
for c in chirpstack door; do [ -f "$L/$c.crt" ] || cert "$L" "$L/ca" $c "extendedKeyUsage=clientAuth"; done
ALG=ML-DSA-44

# the door's OpenSSL group list = the hybrid only, so a client without ML-KEM can't fall back to X25519 (its bridges too)
printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = X25519MLKEM768\n' > "$P/openssl.cnf"
cat > "$M/acl" <<'EOF'
user gateway
topic write +/gateway/+/event/#
topic write +/gateway/+/state/#
topic read +/gateway/+/command/#
EOF
chmod 600 "$M/acl"  # Mosquitto loads it before dropping to its user; world-readable ACLs are deprecated
# the door's bridge to the MQTT broker: only for the stock image (ours connects to the broker itself)
BRIDGE="
# to the MQTT broker: ML-DSA-44 mTLS as chirpstack; its set's CA is checked, not the name (localhost only)
connection broker
address $APP
topic application/+/device/+/event/# out 0
topic application/+/device/+/command/# in 0
bridge_cafile /mosquitto/pq/app/ca.crt
bridge_certfile /mosquitto/pq/app/client.crt
bridge_keyfile /mosquitto/pq/app/client.key
bridge_insecure true
bridge_tls_version tlsv1.3
remote_clientid chirpstack-bridge
cleansession true
notifications false"
[ -z "$IMG" ] || BRIDGE=""
cat > "$M/mosquitto.conf" <<EOF
# ChirpStack's PQ door (made by IoT-PQC scripts/chirpstack_pq_setup.sh): TLS 1.3, X25519MLKEM768 only, ML-DSA-44
allow_anonymous false
listener 8883
cafile /mosquitto/pq/ca.crt
certfile /mosquitto/pq/server.crt
keyfile /mosquitto/pq/server.key
require_certificate true
use_identity_as_username true
tls_version tlsv1.3
acl_file /mosquitto/config/acl

# to ChirpStack's Mosquitto (compose network): TLS 1.3, ECDSA certificates
connection chirpstack
address mosquitto:8884
topic +/gateway/+/event/# out 0
topic +/gateway/+/state/# out 0
topic +/gateway/+/command/# in 0
topic application/+/device/+/event/# in 0
topic application/+/device/+/command/# out 0
bridge_cafile /mosquitto/pq/local/ca.crt
bridge_certfile /mosquitto/pq/local/door.crt
bridge_keyfile /mosquitto/pq/local/door.key
bridge_tls_version tlsv1.3
remote_clientid pq-door
cleansession true
notifications false
$BRIDGE
EOF
cat > "$ML/mosquitto.conf" <<'EOF'
# ChirpStack's Mosquitto (made by IoT-PQC scripts/chirpstack_pq_setup.sh): TLS only, inside the compose network
allow_anonymous false
listener 8884
cafile /tls/ca.crt
certfile /tls/mosquitto.crt
keyfile /tls/mosquitto.key
require_certificate true
use_identity_as_username true
tls_version tlsv1.3
EOF

# the broker's roles: chirpstack and application, issued by its client CA, ML-DSA-44 like the set (kept if present)
for role in chirpstack application ${GW:+gateway}; do
    [ -f "$APP_CERTS/$role.crt" ] || cert "$APP_CERTS" "$APP_CERTS/ClientCA" $role "extendedKeyUsage=clientAuth"
done
cp "$APP_CERTS/chirpstack.crt" "$P/app/client.crt"; cp "$APP_CERTS/chirpstack.key" "$P/app/client.key"; chmod 644 "$P/app/client.key"
cp "$APP_CERTS/CA.crt" "$P/app/ca.crt"
if [ -n "$GW" ]; then  # the Gateway Bridge's identity on the broker: the same key pair in seed-only form, for Go 1.27
    mkdir -p "$P/gw"; cp "$APP_CERTS/CA.crt" "$P/gw/ca.crt"; cp "$APP_CERTS/gateway.crt" "$P/gw/gateway.crt"
    "$OSSL" pkey -provparam ml-dsa.output_formats=seed-only -in "$APP_CERTS/gateway.key" -out "$P/gw/gateway.seed.key"
    chmod 644 "$P/gw/gateway.seed.key"  # as the other keys here: readable by the container's user
fi

# ChirpStack's config: every MQTT connection on its Mosquitto over TLS (the gateway backend of each region, and its
# integration), the downlink wait and the API secret. The application's reply (chirpstack_app.py --reply) goes out in
# the uplink's RX1 window (1 s) only if ChirpStack waits for it: 400 ms between handing the uplink to the integration
# and reading the device's queue (its default, 100 ms, is shorter than the reply's trip through the Pi's broker; the
# uplink events themselves aren't delayed). DOWNLINK_DELAY=100ms: ChirpStack's default again (finding 124)
DD=${DOWNLINK_DELAY:-400ms}
# ChirpStack's API secret (it signs the UI's and API's tokens): a random one, kept so a re-run doesn't log everyone out
[ -s "$P/api_secret" ] || { "$OSSL" rand -base64 32 > "$P/api_secret"; chmod 600 "$P/api_secret"; }
S=$(cat "$P/api_secret")
TLS='  ca_cert="/tls/ca.crt"\n  tls_cert="/tls/chirpstack.crt"\n  tls_key="/tls/chirpstack.key"'
ISRV=ssl://mosquitto:8884/; ITLS=$TLS  # the integration: on ChirpStack's Mosquitto (the door bridges it), or with our
[ -z "$IMG" ] || { ISRV=ssl://$APP/; ITLS='  ca_cert="/pq/ca.crt"\n  tls_cert="/pq/client.crt"\n  tls_key="/pq/client.key"'; }  # image straight to the broker
GSRV=ssl://mosquitto:8884; GT=/tls; GN=chirpstack  # the gateway backend: on ChirpStack's Mosquitto, or (GATEWAY_IMAGE)
[ -z "$GW" ] || { GSRV=ssl://$APP; GT=/pq; GN=client; }  # on the MQTT broker, as the integration (its /pq mount)
for f in "$CS"/configuration/chirpstack/region_*.toml; do
    sed -e "s|server=\"tcp://\\\$MQTT_BROKER_HOST:1883\"|server=\"$GSRV\"|" -e "s|ca_cert=\"\"|ca_cert=\"$GT/ca.crt\"|" \
        -e "s|tls_cert=\"\"|tls_cert=\"$GT/$GN.crt\"|" -e "s|tls_key=\"\"|tls_key=\"$GT/$GN.key\"|" "$f" > "$CC/${f##*/}"
    [ "$(grep -c -E "server=\"$GSRV\"|\"$GT/(ca|$GN)\.(crt|key)\"" "$CC/${f##*/}")" = 4 ] ||
        { echo "$f: no gateway backend server / ca_cert / tls_cert / tls_key lines to set" >&2; exit 1; }
done
T=$CC/chirpstack.toml
awk -v d="$DD" -v s="$S" -v srv="$ISRV" -v tls="$ITLS" '/^[[:space:]]*\[/ {sec = $0; gsub(/[[:space:]]/, "", sec)}
     sec == "[integration.mqtt]" && !m && /^[[:space:]]*server=/ {sub(/server=.*/, "server=\"" srv "\"\n" tls); m = 1}
     sec == "[api]" && !a && /^[[:space:]]*secret=/ {sub(/secret=.*/, "secret=\"" s "\""); a = 1}
     /^[[:space:]]*get_downlink_data_delay=/ {next}
     {print}
     /^[[:space:]]*\[network\][[:space:]]*$/ {print "  get_downlink_data_delay=\"" d "\""}' "$CS/configuration/chirpstack/chirpstack.toml" > "$T"
grep -q "server=\"$ISRV\"" "$T" || { echo "no [integration.mqtt] server= line in chirpstack.toml" >&2; exit 1; }
grep -q "get_downlink_data_delay=\"$DD\"" "$T" || { echo "no [network] in chirpstack.toml" >&2; exit 1; }
grep -q "secret=\"$S\"" "$T" || { echo "no [api] secret= line in chirpstack.toml" >&2; exit 1; }
! grep -r -q -E '^[[:space:]]*server="tcp://' "$CC" || { echo "a plain MQTT server is left in $CC" >&2; exit 1; }

GWS=""
if [ -n "$GW" ]; then  # the Gateway Bridge's config and service
    mkdir -p "$CS/configuration/gateway-bridge-pq"
    cat > "$CS/configuration/gateway-bridge-pq/chirpstack-gateway-bridge.toml" <<EOF
# the Gateway Bridge on Go 1.27 (made by IoT-PQC scripts/chirpstack_pq_setup.sh): ML-DSA-44 mTLS to the MQTT broker
[backend.semtech_udp]
udp_bind="0.0.0.0:1700"

[integration.mqtt]
event_topic_template="as923/gateway/{{ .GatewayID }}/event/{{ .EventType }}"
state_topic_template="as923/gateway/{{ .GatewayID }}/state/{{ .StateType }}"
command_topic_template="as923/gateway/{{ .GatewayID }}/command/#"

[integration.mqtt.auth.generic]
servers=["ssl://$APP"]
ca_cert="/pq/ca.crt"
tls_cert="/pq/gateway.crt"
tls_key="/pq/gateway.seed.key"
EOF
    GWS="
  gateway-bridge-pq:  # the Gateway Bridge on Go 1.27: UDP from this machine's packet forwarder, ML-DSA-44 mTLS to the broker
    image: $GW
    restart: unless-stopped
    ports:
      - \"127.0.0.1:1700:1700/udp\"
    volumes:
      - ./configuration/gateway-bridge-pq/:/etc/chirpstack-gateway-bridge/:ro
      - ./configuration/pq/gw/:/pq/:ro"
fi
CSI=""; [ -z "$IMG" ] || CSI="    image: $IMG
    volumes: !override
      - ./configuration/pq/app/:/pq/:ro"  # the integration's ML-DSA-44 identity and the broker's CA
cat > "$CS/docker-compose.override.yml" <<EOF
# made by IoT-PQC scripts/chirpstack_pq_setup.sh: TLS on every MQTT hop, PQ between machines. Remove this file to go back.
services:
  mosquitto:  # ChirpStack's broker: TLS only, no port outside the compose network
    ports: !reset []
    volumes: !override
      - ./configuration/mosquitto-local/:/mosquitto/config/
      - ./configuration/pq/local/ca.crt:/tls/ca.crt:ro
      - ./configuration/pq/local/mosquitto.crt:/tls/mosquitto.crt:ro
      - ./configuration/pq/local/mosquitto.key:/tls/mosquitto.key:ro
  mosquitto-pq:  # the door for gateways and the bridge to the MQTT broker: X25519MLKEM768 only, ML-DSA-44
    image: eclipse-mosquitto:2
    restart: unless-stopped
    ports:
      - "8883:8883"
    environment:
      - OPENSSL_CONF=/mosquitto/pq/openssl.cnf
    volumes:
      - ./configuration/mosquitto-pq/:/mosquitto/config/
      - ./configuration/pq/:/mosquitto/pq/:ro
    depends_on:
      - mosquitto
  chirpstack:
${CSI:-    volumes: !override}
      - ./configuration/chirpstack-pq/:/etc/chirpstack/:ro
      - ./configuration/pq/local/ca.crt:/tls/ca.crt:ro
      - ./configuration/pq/local/chirpstack.crt:/tls/chirpstack.crt:ro
      - ./configuration/pq/local/chirpstack.key:/tls/chirpstack.key:ro
  # the stock bridges listen on the LAN (UDP 1700, Basics Station 3001) and publish in plain to a listener that no
  # longer exists: off (docker compose --profile stock up -d would start them, without a broker to talk to)
  chirpstack-gateway-bridge:
    profiles: [stock]
  chirpstack-gateway-bridge-basicstation:
    profiles: [stock]$GWS
EOF
echo "[+] $CS/docker-compose.override.yml (MQTT broker: $APP)"
UP="mosquitto-pq chirpstack"; [ -z "$GW" ] || UP="chirpstack gateway-bridge-pq"  # (chirpstack needs mosquitto to start)
echo "next:  cd $CS && docker compose up -d --force-recreate --remove-orphans mosquitto $UP"
echo "Pi:    rsync -a $P/{ca.crt,gateway.crt,gateway.key} <pi-user>@<pi-ip>:chirpstack-pq/   (and certs/ without CA keys, README 0.1)"
echo "UI:    change the admin password (top right: admin > Change password); the API secret is new, so log in again"
