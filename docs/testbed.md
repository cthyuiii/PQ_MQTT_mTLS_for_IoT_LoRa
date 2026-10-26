# The testbed: two Pi 5s

From `git clone` on the Pis to Home Assistant, the application, showing the Pico's readings and answering each one.
The Mac keeps the CA keys: it makes the certificates and ChirpStack's setup, and it built the two images. What has
been run, and where: the last section.

```text
uplink:  Pico W ─Wi-Fi UDP─► virtual_gateway.py ─UDP─► Gateway Bridge ═PQ═► broker ═PQ═► ChirpStack
                             (Pi 1; or the SX1303 HAT's   (Pi 1)             (Pi 2)       (Pi 1)
                              packet forwarder: docs/radio_gateway.md)
event:   ChirpStack ═PQ═► broker ═TLS═► Home Assistant (Pi 1): the reading into its sensors
reply:   Home Assistant ═TLS═► broker ═PQ═► ChirpStack ═PQ═► broker ═PQ═► Gateway Bridge ─► virtual gateway ─► Pico

═PQ═   TLS 1.3, X25519MLKEM768, ML-DSA-44 certificates both ways (mTLS, broker port 18835)
═TLS═  TLS 1.3, X25519MLKEM768, the broker's ML-DSA-44 certificate; the client logs in as `application` (port 18935)
```

## What you need

- **Pi 1** (Pi 5, 4 GB or more): ChirpStack, Postgres, Redis, the Gateway Bridge and Home Assistant in Docker; the
  virtual gateway from the repo (until the radio replaces it).
- **Pi 2** (any Pi 4 / 5): the broker, Mosquitto from Debian.
- **Both:** Raspberry Pi OS (64-bit) on Debian 13 "trixie", for OpenSSL 3.5+ (`openssl version`): Debian 12's 3.0 has
  neither X25519MLKEM768 nor ML-DSA-44.
- **The router:** a DHCP reservation for each Pi, so their addresses stay. The broker's certificate names Pi 2's
  address, and ChirpStack's config holds it.
- **The Mac:** this repo with `certs/` (the CA keys), the images `iot-pqc/chirpstack:4.19.2-pq-aes256` and
  `iot-pqc/gateway-bridge:4.1.2-go1.27`, and `~/chirpstack-docker` (its database: the devices and their keys).
- **The Pico W** on the router's 2.4 GHz Wi-Fi, flashed from the Mac (`pico/run_benchmarks.py`).

Below, `PI1` and `PI2` are the Pis' addresses and `PIUSER` their login: set them in each shell first, e.g.
`PI1=192.168.1.21 PI2=192.168.1.22 PIUSER=macc` (on Pi 1 too: its commands use `$PI2`).

## 1. Both Pis: packages and the repo

```bash
sudo apt update && sudo apt install -y git python3 openssl
openssl version                                  # 3.5 or newer
git clone -b 'macc-personal/test&implementation' https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git ~/PQ_MQTT_mTLS_for_IoT_LoRa
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa                   # later: git pull
```

No `--recurse-submodules`: the ChirpStack fork is only needed to build its image, on the Mac. An existing clone on
another branch: `git fetch origin "+refs/heads/$B:refs/remotes/origin/$B"` and `git switch -c "$B" --track "origin/$B"`
with `B='macc-personal/test&implementation'` (quoted: the `&`).

## 2. The Mac: the broker's certificate for its new address, to Pi 2

```bash
# repo root. The CA and the broker's key stay, so every client certificate stays valid
export OSSL=/opt/homebrew/opt/openssl@3/bin/openssl
bash scripts/gen_certs.sh --server-names MLDSA44 IP:$PI2
# certs/ without the CA keys, ChirpStack's key and the application's password (the broker has only its hash)
X=(--exclude CA.key --exclude ClientCA.key --exclude update.key --exclude '*.srl' --exclude chirpstack.key
   --exclude application.password)
rsync -a --delete --delete-excluded "${X[@]}" certs/ $PIUSER@$PI2:PQ_MQTT_mTLS_for_IoT_LoRa/certs/
```

Pi 1 needs nothing from `certs/`: ChirpStack's and the gateway's identities come with its setup (step 4), and Home
Assistant gets the CA and the password through its UI (step 6).

## 3. Pi 2: the broker

```bash
sudo apt install -y mosquitto && sudo systemctl disable --now mosquitto   # the package's own broker: plain, off
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa
scripts/broker.sh start          # as yourself, not sudo; expect "MLDSA44 :18835 / :18935  up"
scripts/broker.sh log            # one line per connection and per message; Ctrl-C stops following, not the broker
(crontab -l 2>/dev/null; echo "@reboot $PWD/scripts/broker.sh start") | crontab -     # at every boot
```

`failed to start` names the cause: a port in use (another broker: `scripts/broker.sh stop`, or the old
`~/iot-pqc-chain-broker/stop.sh`), or a missing `certs/MLDSA44` file (step 2). `BROKER_ACL=1 scripts/broker.sh start`
also limits each certificate to its own topics on :18835 (off so far; the login on :18935 always has its limits).

## 4. Pi 1: Docker, ChirpStack and the Gateway Bridge

```bash
# Pi 1, once: Docker with Compose 2.24.4+ (the override's !reset / !override); log out and in for the docker group
curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker $USER
```

```bash
# the Mac, repo root: ChirpStack's setup for Pi 1 and the broker on Pi 2, in a folder of its own (the setup signs
# ChirpStack's and the gateway's certificates with the client CA's key, which stays here); the API secret kept, so
# the database's API keys stay valid
git clone https://github.com/chirpstack/chirpstack-docker.git ~/chirpstack-docker-pi
mkdir -p ~/chirpstack-docker-pi/configuration/pq
cp -p ~/chirpstack-docker/configuration/pq/api_secret ~/chirpstack-docker-pi/configuration/pq/
CHIRPSTACK_IMAGE=iot-pqc/chirpstack:4.19.2-pq-aes256 GATEWAY_IMAGE=iot-pqc/gateway-bridge:4.1.2-go1.27 \
  bash scripts/chirpstack_pq_setup.sh $PI1 $PI2:18835 ~/chirpstack-docker-pi
rsync -a --exclude ca.key ~/chirpstack-docker-pi/ $PIUSER@$PI1:chirpstack-docker/       # (unused CA keys stay)
docker save iot-pqc/chirpstack:4.19.2-pq-aes256 iot-pqc/gateway-bridge:4.1.2-go1.27 | gzip |
  ssh $PIUSER@$PI1 'gunzip | docker load'                                              # arm64, built on the Mac
# the Mac: its ChirpStack off (two on one broker as the same `chirpstack` would fight), then the database to Pi 1:
# the devices, their keys and frame counters (a Pico's saved FCnt still fits)
cd ~/chirpstack-docker && docker compose stop chirpstack gateway-bridge-pq
docker compose exec -T postgres pg_dump -U chirpstack -Fc chirpstack | ssh $PIUSER@$PI1 'umask 077; cat > cs.dump'
docker compose stop; cd -
```

```bash
# Pi 1: the database first (fresh: its init script adds the extensions), the dump into it, then the rest
cd ~/chirpstack-docker && docker compose up -d postgres
until docker compose exec -T postgres psql -U chirpstack -tAc "select 1 from pg_extension where extname='hstore'" | grep -q 1; do sleep 1; done
docker compose exec -T postgres pg_restore -U chirpstack -d chirpstack < ~/cs.dump && rm ~/cs.dump
docker compose up -d --remove-orphans postgres redis chirpstack gateway-bridge-pq
docker compose ps; docker compose logs chirpstack | grep -i -E 'mqtt|error|warn' | tail -5
```

On Pi 2, `scripts/broker.sh log` now shows 16 connections as `chirpstack` (one per enabled region, and the
integration) and one as `gateway`. Docker starts all four again at every boot (`restart: unless-stopped`).

- **ChirpStack's UI:** `http://PI1:8080`, plain HTTP on the LAN: change the admin password first (admin, top right).
- **Redis restarting** with "Unsupported system page size" is the Pi 5's 16K-page kernel; the 4K one fixes it:
  `echo kernel=kernel8.img | sudo tee -a /boot/firmware/config.txt && sudo reboot`.
- **Day to day,** in `~/chirpstack-docker`: `docker compose restart chirpstack gateway-bridge-pq`,
  `docker compose logs -f chirpstack`, `docker compose stop` (README "Start, stop and restart").

## 5. Pi 1: the virtual gateway

The Pico's "air" until the radio works: its frames as UDP on port 1680, handed to the Gateway Bridge on 127.0.0.1:1700
(Python only, nothing to build). With the SX1303 HAT, the packet forwarder takes its place: `docs/radio_gateway.md`.

```bash
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa && mkdir -p results/testbed
nohup python3 -u network/virtual_gateway.py --air 0.0.0.0:1680 >> results/testbed/vgw.log 2>&1 &
(crontab -l 2>/dev/null; echo "@reboot cd $PWD && python3 -u network/virtual_gateway.py --air 0.0.0.0:1680 >> results/testbed/vgw.log 2>&1") | crontab -
pkill -f 'virtual_gateway.py --air'      # (to stop it)
```

## 6. Pi 1: Home Assistant, the application

Home Assistant 2026.10.4 (the version tested; its OpenSSL is 3.5.9) in Docker, its configuration in `~/homeassistant`.
It reads ChirpStack's uplink events on the broker's :18935 with the login, and its automation answers each FPort 1
uplink with "ack <FCnt>" on ChirpStack's command topic, as `chirpstack_app.py --reply` did. Nothing else may answer
too (no `scripts/app.sh` on the testbed): ChirpStack would queue two downlinks per uplink.

```bash
# Pi 1: first start (it writes ~/homeassistant/configuration.yaml)
mkdir -p ~/homeassistant
docker run -d --name homeassistant --restart=unless-stopped -e TZ=Asia/Singapore -v ~/homeassistant:/config \
  --network=host ghcr.io/home-assistant/home-assistant:2026.10.4
```

Then in a browser, `http://PI1:8123`:

1. Create the owner account.
2. **Settings → Devices & services → Add integration → MQTT.** Broker: Pi 2's address (the name its certificate
   carries). Port: `18935`. Username: `application`. Password: on the Mac, `cat certs/MLDSA44/application.password`.
3. In the same form, open **Other settings:** Broker certificate validation: **Custom**; Upload custom CA certificate
   file: the Mac's `certs/MLDSA44/CA.crt`. Leave "Ignore broker certificate validation" and "Use a client
   certificate" off. Submit. (Home Assistant moves itself to MQTT 5; the broker takes both.)

```bash
# Pi 1: the Pico's sensors and the answering automation (network/homeassistant/pico.yaml), then one restart: the
# automation subscribes to its MQTT topic as Home Assistant starts, so after the integration exists
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa
sudo mkdir -p ~/homeassistant/packages && sudo cp network/homeassistant/pico.yaml ~/homeassistant/packages/
printf 'homeassistant:\n  packages: !include_dir_named packages\n' | sudo tee -a ~/homeassistant/configuration.yaml
docker restart homeassistant
```

On Pi 2, `scripts/broker.sh log` shows `user 'application'` from Pi 1, and `application -> refused (ACL):
homeassistant/status`: Home Assistant's own status message, which the login may not send (harmless). Home Assistant
reconnects by itself when the broker restarts.

The sensors: **Pico temperature**, **Pico humidity**, **Pico uplink counter** (Settings → Entities). Temperature and
humidity come from FPort 1 frames (lorawan11_256: ChirpStack has decrypted the reading). FPort 2 frames
(lorawan11_e2e) carry the 256-bit layer inside, which Home Assistant can't open: the counter moves, the readings keep
their last value, and no answer goes back (the Pico's lorawan11_e2e block gets no replies).

## 7. The Pico

```bash
# the Mac, repo root, the Pico on USB: its keys from the provisioning file (exported, not printed)
eval "$(python3 -c "import json,os; d=json.load(open(os.path.expanduser('~/.cache/iot-pqc/phase1/devices.json')))['devices']['pico-1.1-abp']; print('export APP_KEYS='+d['app_s_key']+d['f_nwk_s_int_key']+d['s_nwk_s_int_key']+d['e2e_key'])")"
export DEV_ADDR=012345c1 AIR=$PI1:1680 REPLY_WAIT_MS=2000 BROKER=$PI2
export WIFI_SSID='<the router, 2.4 GHz>' WIFI_PASS='<password>'
python3 pico/run_benchmarks.py --board rp2040 --test mqtt --match 'chirpstack device' --tag testbed_run1
```

A new `--tag` for each run, or the run before is overwritten.

## 8. Did it work?

```bash
# Pi 1, repo root: the virtual gateway (the Pico: DevAddr 012345c1, DevEUI 0000000000000c11)
A=012345c1; E=0000000000000c11
grep -c "^sent.*DevAddr $A " results/testbed/vgw.log      # 1. frames forwarded to the Gateway Bridge
grep -c "^acked DevAddr $A " results/testbed/vgw.log     # 2. of them, taken by the Bridge
(cd ~/chirpstack-docker && docker compose logs --since 1h chirpstack) | grep -c "Publishing event.*/$E/event/up"
                                                         # 3. MIC checked and decrypted by ChirpStack
grep -c '^downlink' results/testbed/vgw.log              # 5. the answers back out to the Pico
# Pi 2, repo root: 4. the messages between them, e.g. "chirpstack -> application: application/.../event/up"
# and "application -> chirpstack: application/.../command/down" (Home Assistant's answer)
grep -- ' -> ' results/broker.log | grep -v 'new connection' | tail -6
# the Mac: the Pico's replies in time, per uplink (lorawan11_256: all; lorawan11_e2e: none, step 6)
awk -F, 'NR>1 && $6=="uplink" {n[$5]++; if ($18 > 0) r[$5]++} END {for (k in n) print k, r[k]+0 "/" n[k]}' \
  results/pipeline_msgs_raw_pico_rp2040_testbed_run1.csv
```

And Home Assistant's sensors follow the readings. A frame the Pico sent that never reached the virtual gateway
(step 1 lower than the Pico's count) was lost on Wi-Fi: UDP, no retry.

## Reboots

- **Pi 2:** cron starts the broker; ChirpStack, the Gateway Bridge and Home Assistant reconnect by themselves.
- **Pi 1:** Docker starts ChirpStack, the Gateway Bridge and Home Assistant; cron starts the virtual gateway.

## What has been run, and where

Nothing here has run on the Pis yet. Run elsewhere (26 Oct):

- **Steps 1 and 3 on Debian 13** (a `debian:trixie` container on the Mac, arm64 like the Pi; OpenSSL 3.5.7,
  Mosquitto 2.0.21), from a copy of the committed tree: the broker started as cron starts it (a bare PATH), as a
  normal user, and printed each connection and message; `virtual_gateway.py --selftest` (step 5); ChirpStack's part
  played with its certificate.
- **Step 6 on Home Assistant 2026.10.4** (its container on the Mac, next to that broker), from its default
  configuration, the steps as written (the MQTT form filled through the API the UI uses, the CA file uploaded the
  same way): it connected over TLS 1.3 with the login (the broker takes X25519MLKEM768 and ML-DSA-44 only), filled
  the three sensors from FPort 1 events, kept them on an FPort 2 event, and answered 20 of 20 FPort 1 events with
  "ack <FCnt>" on ChirpStack's command topic, 3.7 ms median (60 ms max) from event to command. After a broker
  restart it reconnected and kept answering. Without the restart after the integration, the automation stays
  unsubscribed (seen: hence the restart in step 6).
- **Step 4** on the Mac only: the setup into its own folder gives the same compose configuration as the running one
  (but for the project name), and the database dump restores into a fresh Postgres 14 with its 7 devices and frame
  counters. The images, Docker and Redis on a Pi 5: not tried.
- **The chain itself** (Pico → virtual gateway → Gateway Bridge → broker → ChirpStack → application and back): on
  the Mac with the broker on a Pi, 30 of 30 replies (Pico run 7), with `chirpstack_app.py` as the application.
