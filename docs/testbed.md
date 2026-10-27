# The testbed: a Windows PC and two Pi 5s

From `git clone` to Home Assistant, the application, showing the Pico's readings and answering each one. The Mac keeps
the CA keys: it makes the certificates and ChirpStack's setup, and it built the Gateway Bridge's image. What has been
run, and where: the last section.

```text
uplink:  Pico W ─Wi-Fi UDP─► virtual_gateway.py ─UDP─► Gateway Bridge ═PQ═► broker ═PQ═► ChirpStack
                             (gateway Pi; later the SX1303 HAT's   (gateway Pi)   (broker Pi)  (the PC)
                              packet forwarder: docs/radio_gateway.md)
event:   ChirpStack ═PQ═► broker ═TLS═► Home Assistant (the PC): the reading into its sensors
reply:   Home Assistant ═TLS═► broker ═PQ═► ChirpStack ═PQ═► broker ═PQ═► Gateway Bridge ─► virtual gateway ─► Pico

═PQ═   TLS 1.3, X25519MLKEM768, ML-DSA-44 certificates both ways (mTLS, broker port 18835)
═TLS═  TLS 1.3, X25519MLKEM768, the broker's ML-DSA-44 certificate; the client logs in as `application` (port 18935)
```

## What you need

- **The PC** (Windows 11, x86_64): ChirpStack, Postgres, Redis and Home Assistant, in Docker Desktop. Docker Desktop
  runs only while someone is signed in to Windows: after a restart, sign in again. Sleep off.
- **The broker Pi** (the one that ran the old ChirpStack and Home Assistant): the broker. It runs Debian 12, whose
  Mosquitto package is on OpenSSL 3.0 (neither X25519MLKEM768 nor ML-DSA-44), so the broker is the old
  mosquitto-oqs's Mosquitto, built on the Pi's own OpenSSL 3.6.3: only its program, with our config and certificates
  (steps 1 and 3). At least 1 GB free on its card (`df -h /`).
- **The gateway Pi** (the one with the SX1303 HAT): the packet forwarder it already runs, our Gateway Bridge in
  Docker, and the virtual gateway (Python only) until the Pico has a radio.
- **The router:** a DHCP reservation for the PC and each Pi, so their addresses stay. The broker's certificate names
  the broker Pi's address, and ChirpStack's and the Gateway Bridge's configs hold it.
- **The Mac,** on the router's network for the copies: this repo with `certs/` (the CA keys), the image
  `iot-pqc/gateway-bridge:4.1.2-go1.27` (arm64, for the gateway Pi), and `~/chirpstack-docker` (its database: the
  devices and their keys).
- **The Pico W** on the router's 2.4 GHz Wi-Fi, flashed from the Mac (`pico/run_benchmarks.py`).

Below, `BRK`, `GW` and `PC` are the broker Pi's, the gateway Pi's and the PC's addresses (`ipconfig` on the PC) and
`PIUSER` the Pis' login: set them in each Mac or Pi shell first, the lab's `BRK=192.168.0.50 GW=192.168.0.40
PIUSER=admin` (`hostname -I` on each Pi). The PC's commands are PowerShell.

## 0. The old setup: saved, then off

ChirpStack, its Mosquitto and Home Assistant on the broker Pi, and the stock Gateway Bridge on the gateway Pi (ours
takes its port, 1700). The packet forwarder stays. `disable --now` deletes nothing (the services only stop starting
at boot), and of their files this plan changes one: the packet forwarder's config (step 6). A copy of
each first anyway, into `~/old-setup-<date>` on each Pi, then on the Mac. Service names as
`systemctl list-units --type=service` and `docker ps` show them.

```bash
# broker Pi. umask 077: the copies hold keys and passwords, readable by you only
umask 077; B=~/old-setup-$(date +%F); mkdir -p $B
systemctl cat chirpstack mosquitto-oqs > $B/units.txt         # each service's command line: where its config is
sudo tar czf - /etc/chirpstack > $B/etc-chirpstack.tgz
sudo -u postgres pg_dump -Fc chirpstack > $B/chirpstack.dump    # its database (`sudo -u postgres psql -l`: the name)
redis-cli --rdb $B/redis.rdb                                    # its Redis, if one runs
sudo tar czf - /opt/mosquitto-oqs/config > $B/mosquitto-oqs.tgz        # its config (units.txt)
docker inspect -f '{{.Config.Image}} {{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' homeassistant > $B/ha.txt
docker update --restart=no homeassistant && docker stop homeassistant      # stopped, so its database is whole
sudo tar czf - -C ~/pqc-testbed/homeassistant/config . > $B/ha-config.tgz   # its /config (ha.txt)
sudo systemctl disable --now chirpstack mosquitto-oqs
pg_restore -f /dev/null $B/chirpstack.dump && echo dump whole   # a full card cuts a copy short (df -h /)
```

```bash
# gateway Pi
umask 077; B=~/old-setup-$(date +%F); mkdir -p $B
systemctl cat chirpstack-gateway-bridge lora-packet-forwarder > $B/units.txt
sudo tar czf - /etc/chirpstack-gateway-bridge > $B/etc-gateway-bridge.tgz
sudo tar czf - ~/sx1302_hal_rpi5-master/packet_forwarder > $B/packet-forwarder.tgz   # the forwarder's folder
sudo systemctl disable --now chirpstack-gateway-bridge
```

```bash
# the Mac: both copies, outside the repo, then checked whole
rsync -a "$PIUSER@$BRK:old-setup-*" ~/old-setup-broker-pi/
rsync -a "$PIUSER@$GW:old-setup-*" ~/old-setup-gateway-pi/
for f in ~/old-setup-*-pi/*/*.tgz; do gzip -t "$f" || echo "CUT SHORT: $f"; done
```

Back to the old setup: ours off first (broker Pi: `scripts/broker.sh stop` and its line out of `crontab -e`; gateway
Pi: `docker rm -f gateway-bridge-pq`), the forwarder's folder back (`sudo tar xzf packet-forwarder.tgz -C /`), then
`sudo systemctl enable --now` the same services and `docker update --restart=unless-stopped homeassistant &&
docker start homeassistant`. On a fresh card instead: the archives with `sudo tar xzf <file> -C /` (Home Assistant's:
`-C` its folder), and the database with `sudo -u postgres pg_restore -d chirpstack < chirpstack.dump` into an empty
`chirpstack` database. A whole-card image as well, if wanted: Raspberry Pi OS's SD Card Copier, onto a card in a USB
reader.

## 1. The Pis: packages and the repo

```bash
# broker Pi: the old mosquitto-oqs's Mosquitto (its program only, not its config) on its OpenSSL 3.6.3, with the
# environment its unit gave it (step 0's units.txt). OSSL: the OpenSSL broker.sh asks whether oqs-provider loads
export MOSQUITTO=/opt/mosquitto-oqs/sbin/mosquitto OSSL=/opt/openssl-3.6.3/bin/openssl \
  LD_LIBRARY_PATH=/opt/openssl-3.6.3/lib:/opt/openssl-3.6.3/lib64 OPENSSL_MODULES=/opt/openssl-3.6.3/lib/ossl-modules
ldd $MOSQUITTO | grep -E 'libssl|libcrypto'   # /opt/openssl-3.6.3/..., not /usr/lib/aarch64-linux-gnu/ (3.0)
$MOSQUITTO -h | head -1; $OSSL version        # mosquitto version 2.x; OpenSSL 3.6.3
# both Pis (the gateway Pi: for the virtual gateway). --depth 1: the files (1 MB), not the history (300 MB)
git clone --depth 1 -b 'macc-personal/test&implementation' https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git ~/PQ_MQTT_mTLS_for_IoT_LoRa
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa                         # later: git pull
```

No `--recurse-submodules`: the ChirpStack fork is only needed to build its image, on the PC. An existing clone on
another branch: `git fetch origin "+refs/heads/$B:refs/remotes/origin/$B"` and `git switch -c "$B" --track "origin/$B"`
with `B='macc-personal/test&implementation'` (quoted: the `&`).

## 2. The Mac: the broker's certificate for its address, to the broker Pi

```bash
# repo root. The CA and the broker's key stay, so every client certificate stays valid
export OSSL=/opt/homebrew/opt/openssl@3/bin/openssl
bash scripts/gen_certs.sh --server-names MLDSA44 IP:$BRK
# certs/ without the CA keys, ChirpStack's key and the application's password (the broker has only its hash)
X=(--exclude CA.key --exclude ClientCA.key --exclude update.key --exclude '*.srl' --exclude chirpstack.key
   --exclude application.password)
rsync -a --delete --delete-excluded "${X[@]}" certs/ $PIUSER@$BRK:PQ_MQTT_mTLS_for_IoT_LoRa/certs/
```

## 3. The broker Pi: the broker

```bash
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa
# step 1's export, in this shell too
scripts/broker.sh start          # as yourself, not sudo; expect "MLDSA44 :18835 / :18935  up"
scripts/broker.sh log            # one line per connection and per message; Ctrl-C stops following, not the broker
E="MOSQUITTO=$MOSQUITTO OSSL=$OSSL LD_LIBRARY_PATH=$LD_LIBRARY_PATH OPENSSL_MODULES=$OPENSSL_MODULES"
(crontab -l 2>/dev/null; echo "@reboot $E $PWD/scripts/broker.sh start") | crontab -   # at every boot
```

```bash
# the Mac, repo root: X25519 alone refused; X25519MLKEM768 taken, with a certificate that names the broker's address
O=/opt/homebrew/opt/openssl@3/bin/openssl
$O s_client -connect $BRK:18935 -groups X25519 -brief </dev/null 2>&1 | grep -o 'handshake failure'
$O s_client -connect $BRK:18935 -groups X25519MLKEM768 -CAfile certs/MLDSA44/CA.crt -verify_ip $BRK -brief \
  </dev/null 2>&1 | grep -E '^(Verification|Negotiated)'   # Verification: OK, and the group X25519MLKEM768
```

`failed to start` names the cause: a port in use (another broker: `scripts/broker.sh stop`), or a missing
`certs/MLDSA44` file (step 2). `BROKER_ACL=1 scripts/broker.sh start` also limits each certificate to its own topics
on :18835 (off so far; the login on :18935 always has its limits).

## 4. The PC: Docker Desktop and ChirpStack's image

The Mac's ChirpStack image is arm64; the PC (x86_64) builds its own from the same source, once (tens of minutes).
Install Docker Desktop (WSL 2) and Git for Windows; in Docker Desktop's settings, "Start Docker Desktop when you sign
in". Then:

```powershell
# PC. Git for Windows turns line ends into Windows' by default, which breaks the build's shell scripts
git config --global core.autocrlf false
git clone --recurse-submodules -b "macc-personal/test&implementation" https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git $HOME\PQ_MQTT_mTLS_for_IoT_LoRa
cd $HOME\PQ_MQTT_mTLS_for_IoT_LoRa
docker build -f scripts/chirpstack/Dockerfile -t iot-pqc/chirpstack:4.19.2-pq-aes256 network/chirpstack
```

## 5. ChirpStack on the PC

```bash
# the Mac, repo root: ChirpStack's setup for the PC and the broker Pi, in a folder of its own (the setup signs
# ChirpStack's and the gateway's certificates with the client CA's key, which stays here); the API secret kept, so
# the database's API keys stay valid
git clone https://github.com/chirpstack/chirpstack-docker.git ~/chirpstack-docker-pc
mkdir -p ~/chirpstack-docker-pc/configuration/pq
cp -p ~/chirpstack-docker/configuration/pq/api_secret ~/chirpstack-docker-pc/configuration/pq/
CHIRPSTACK_IMAGE=iot-pqc/chirpstack:4.19.2-pq-aes256 GATEWAY_IMAGE=iot-pqc/gateway-bridge:4.1.2-go1.27 \
  bash scripts/chirpstack_pq_setup.sh $PC $BRK:18835 ~/chirpstack-docker-pc
# the Mac's ChirpStack off (two on one broker as the same `chirpstack` would fight), then its database into the
# folder: the devices, their keys and frame counters (a Pico's saved FCnt still fits)
cd ~/chirpstack-docker && docker compose stop chirpstack gateway-bridge-pq && docker compose up -d postgres && sleep 5
(umask 077; docker compose exec -T postgres pg_dump -U chirpstack -Fc chirpstack > ~/chirpstack-docker-pc/cs.dump)
docker compose stop; cd -
# one file for the PC, without the unused CA keys. It holds keys: delete it wherever it was copied
(umask 077; tar czf ~/cs-pc.tgz --exclude ca.key -C ~ chirpstack-docker-pc)
```

Copy `~/cs-pc.tgz` into the PC's home folder (a USB stick, or `scp` if the PC runs Windows' OpenSSH server), then:

```powershell
# PC, in your home folder: the database first (fresh: its init script adds the extensions), the dump into it, then
# ChirpStack. PowerShell has no `<`, so the dump goes in with `docker compose cp`
tar -xzf cs-pc.tgz; del cs-pc.tgz
cd chirpstack-docker-pc
docker compose up -d postgres; Start-Sleep 30
docker compose exec postgres psql -U chirpstack -c '\dx'          # hstore and pg_trgm listed: ready
docker compose cp cs.dump postgres:/tmp/cs.dump
docker compose exec postgres pg_restore -U chirpstack -d chirpstack /tmp/cs.dump
docker compose exec postgres rm /tmp/cs.dump; del cs.dump
docker compose up -d --remove-orphans postgres redis chirpstack
docker compose logs --tail 20 chirpstack
```

The compose file's `gateway-bridge-pq` stays off here: it runs on the gateway Pi (step 6), next to the radio. On the
broker Pi, `scripts/broker.sh log` now shows 16 connections as `chirpstack` (one per enabled region, and the
integration). Docker Desktop starts all three again when it starts (`restart: unless-stopped`).

- **ChirpStack's UI:** `http://PC:8080`, plain HTTP on the LAN: change the admin password first (admin, top right).
  From another machine, Windows' firewall must let it in (8123 too, step 8): in PowerShell as administrator,
  `New-NetFirewallRule -DisplayName IoT-PQC -Direction Inbound -Protocol TCP -LocalPort 8080,8123 -Action Allow
  -Profile Private`, with the router's network set to Private in Windows' network settings.
- **Day to day,** in `chirpstack-docker-pc`: `docker compose restart chirpstack`, `docker compose logs -f chirpstack`,
  `docker compose stop`.

## 6. The gateway Pi: the Gateway Bridge

```bash
# gateway Pi, once: Docker; log out and in for the docker group
curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker $USER
```

```bash
# the Mac: the Bridge's config and ML-DSA-44 identity (step 5 made them; the config names the broker Pi), and its image
rsync -a ~/chirpstack-docker-pc/configuration/gateway-bridge-pq ~/chirpstack-docker-pc/configuration/pq/gw $PIUSER@$GW:gwb/
docker save iot-pqc/gateway-bridge:4.1.2-go1.27 | gzip | ssh $PIUSER@$GW 'gunzip | docker load'
```

```bash
# gateway Pi: the Bridge takes UDP on 127.0.0.1:1700 only (the plain hop stays on this Pi), mTLS to the broker
docker run -d --name gateway-bridge-pq --restart unless-stopped -p 127.0.0.1:1700:1700/udp \
  -v ~/gwb/gateway-bridge-pq:/etc/chirpstack-gateway-bridge:ro -v ~/gwb/gw:/pq:ro iot-pqc/gateway-bridge:4.1.2-go1.27
docker logs gateway-bridge-pq 2>&1 | tail -5
# the packet forwarder: where its config is, and where it sends
systemctl cat lora-packet-forwarder | grep -E 'WorkingDirectory|ExecStart'
grep -E '"(gateway_ID|server_address|serv_port_up|serv_port_down|freq)"' <the file after -c>   # the lab's:
#   ~/sx1302_hal_rpi5-master/packet_forwarder/global_conf.json.sx1250.AS923.SPI
```

- `server_address` must be `127.0.0.1` (`localhost` may resolve to `::1`, where Docker doesn't listen) and both ports
  `1700`. Changed: `sudo systemctl restart lora-packet-forwarder`; `journalctl -u lora-packet-forwarder -n 40` then
  shows `PUSH_ACK` and `PULL_ACK` received: the Bridge answers.
- The `freq` values must be AS923's, about 922-924 MHz: ChirpStack and the Bridge use AS923 (`as923/` topics).
- The `gateway_ID` goes into ChirpStack's UI: Gateways → Add gateway. The virtual gateway's (`0102030405060708`) came
  with the database.

On the broker Pi, `scripts/broker.sh log` shows a connection as `gateway`.

## 7. The gateway Pi: the virtual gateway

The Pico's "air" until its radio works: its frames as UDP on port 1680, handed to the Gateway Bridge on 127.0.0.1:1700,
next to the packet forwarder's.

```bash
cd ~/PQ_MQTT_mTLS_for_IoT_LoRa && mkdir -p results/testbed
nohup python3 -u network/virtual_gateway.py --air 0.0.0.0:1680 >> results/testbed/vgw.log 2>&1 &
(crontab -l 2>/dev/null; echo "@reboot cd $PWD && python3 -u network/virtual_gateway.py --air 0.0.0.0:1680 >> results/testbed/vgw.log 2>&1") | crontab -
pkill -f 'virtual_gateway.py --air'      # (to stop it)
```

## 8. The PC: Home Assistant, the application

Home Assistant 2026.10.4 (the version tested; its OpenSSL is 3.5.9) in Docker, its configuration in a Docker volume
(its SQLite database is slow on a folder shared from Windows). It reads ChirpStack's uplink events on the broker's
:18935 with the login, and its automation answers each FPort 1 uplink with "ack <FCnt>" on ChirpStack's command topic,
as `chirpstack_app.py --reply` did. Nothing else may answer too (no `scripts/app.sh` on the testbed): ChirpStack would
queue two downlinks per uplink.

```powershell
# PC: first start (it writes /config/configuration.yaml)
docker run -d --name homeassistant --restart=unless-stopped -e TZ=Asia/Singapore -v ha_config:/config -p 8123:8123 ghcr.io/home-assistant/home-assistant:2026.10.4
```

Then in a browser, `http://localhost:8123` on the PC:

1. Create the owner account.
2. **Settings → Devices & services → Add integration → MQTT.** Broker: the broker Pi's address (the name its
   certificate carries). Port: `18935`. Username: `application`. Password: on the Mac,
   `cat certs/MLDSA44/application.password`.
3. In the same form, open **Other settings:** Broker certificate validation: **Custom**; Upload custom CA certificate
   file: the PC's `chirpstack-docker-pc\configuration\pq\app\ca.crt` (the broker's CA, the Mac's
   `certs/MLDSA44/CA.crt`). Leave "Ignore broker certificate validation" and "Use a client certificate" off. Submit.
   (Home Assistant moves itself to MQTT 5; the broker takes both.)

```powershell
# PC, repo root: the Pico's sensors and the answering automation (network/homeassistant/pico.yaml), then one restart:
# the automation subscribes to its MQTT topic as Home Assistant starts, so after the integration exists
docker exec homeassistant mkdir -p /config/packages
docker cp network/homeassistant/pico.yaml homeassistant:/config/packages/pico.yaml
docker exec -it homeassistant sh
#   inside it: printf 'homeassistant:\n  packages: !include_dir_named packages\n' >> /config/configuration.yaml; exit
docker restart homeassistant
```

On the broker Pi, `scripts/broker.sh log` shows `user 'application'` from the PC, and `application -> refused (ACL):
homeassistant/status`: Home Assistant's own status message, which the login may not send (harmless). Home Assistant
reconnects by itself when the broker restarts.

The sensors: **Pico temperature**, **Pico humidity**, **Pico uplink counter** (Settings → Entities). Temperature and
humidity come from FPort 1 frames (lorawan11_256: ChirpStack has decrypted the reading). FPort 2 frames
(lorawan11_e2e) carry the 256-bit layer inside, which Home Assistant can't open: the counter moves, the readings keep
their last value, and no answer goes back (the Pico's lorawan11_e2e block gets no replies).

## 9. The Pico

```bash
# the Mac, repo root, the Pico on USB: its keys from the provisioning file (exported, not printed)
eval "$(python3 -c "import json,os; d=json.load(open(os.path.expanduser('~/.cache/iot-pqc/phase1/devices.json')))['devices']['pico-1.1-abp']; print('export APP_KEYS='+d['app_s_key']+d['f_nwk_s_int_key']+d['s_nwk_s_int_key']+d['e2e_key'])")"
export DEV_ADDR=012345c1 AIR=$GW:1680 REPLY_WAIT_MS=2000 BROKER=$BRK
export WIFI_SSID='<the router, 2.4 GHz>'; read -rs WIFI_PASS; export WIFI_PASS
python3 pico/run_benchmarks.py --board rp2040 --test mqtt --match 'chirpstack device' --tag testbed_run1
```

A new `--tag` for each run, or the run before is overwritten.

Then over the radio (`docs/radio_gateway.md`, last section): the Pico on its SX1262 board, the antenna on. No Wi-Fi
in that build, so no `WIFI_*`; `REPLY_WAIT_MS` (any value) opens RX1 and RX2 after each uplink. One board per device:
two boards with the same `DEV_ADDR` would each count their own FCnt, and ChirpStack refuses the lower one.

```bash
# the Mac, repo root, the Pico on USB; RadioLib once: arduino-cli lib install RadioLib@7.8.1
export AIR=radio REPLY_WAIT_MS=1
python3 pico/run_benchmarks.py --board rp2040 --test mqtt --match 'chirpstack device' --tag testbed_radio1   # Pico 2 W: --board rp2350
# gateway Pi: the Pico's frames as the radio heard them, and the replies sent
journalctl -u lora-packet-forwarder --since '15 min ago' | grep -E 'JSON (up|down)' | tail -4
```

## 10. Did it work?

```bash
# gateway Pi, repo root: the virtual gateway (the Pico: DevAddr 012345c1)
A=012345c1
grep -c "^sent.*DevAddr $A " results/testbed/vgw.log      # 1. frames forwarded to the Gateway Bridge
grep -c "^acked DevAddr $A " results/testbed/vgw.log     # 2. of them, taken by the Bridge
grep -c '^downlink' results/testbed/vgw.log              # 5. the answers back out to the Pico
# broker Pi, repo root: 4. the messages between them, e.g. "chirpstack -> application: application/.../event/up"
# and "application -> chirpstack: application/.../command/down" (Home Assistant's answer)
grep -- ' -> ' results/broker.log | grep -v 'new connection' | tail -6
# the Mac: the Pico's replies in time, per uplink (lorawan11_256: all; lorawan11_e2e: none, step 8)
awk -F, 'NR>1 && $6=="uplink" {n[$5]++; if ($18 > 0) r[$5]++} END {for (k in n) print k, r[k]+0 "/" n[k]}' \
  results/pipeline_msgs_raw_pico_rp2040_testbed_run1.csv
```

```powershell
# PC, in chirpstack-docker-pc: 3. MIC checked and decrypted by ChirpStack (the Pico: DevEUI 0000000000000c11)
(docker compose logs --since 1h chirpstack | Select-String 'Publishing event.*/0000000000000c11/event/up').Count
```

And Home Assistant's sensors follow the readings. A frame the Pico sent that never reached the virtual gateway
(step 1 lower than the Pico's count) was lost on Wi-Fi: UDP, no retry.

## Reboots

- **Broker Pi:** cron starts the broker; ChirpStack, the Gateway Bridge and Home Assistant reconnect by themselves.
- **Gateway Pi:** systemd starts the packet forwarder, Docker the Gateway Bridge, cron the virtual gateway.
- **The PC:** once someone signs in, Docker Desktop starts ChirpStack and Home Assistant.

## What has been run, and where

This layout (the PC, 27 Oct) has run only in part: nothing on Windows or Docker Desktop yet; on the Pis, step
3. Run elsewhere:

- **Step 9's radio firmware** (27 Oct): compiles for the Pico W and the Pico 2 W with RadioLib 7.8.1 (`AIR=radio`,
  no Wi-Fi variables set); the Wi-Fi build (`AIR=<host:port>`) still compiles. Not flashed, not run on the radio.
- **Step 0's copies** (27 Oct, a `debian:trixie` container, arm64; stand-ins for the old services: a `chirpstack`
  database with a row, Redis, a config folder, a forwarder folder): every file written `-rw-------` and owned by the
  user, the database dump restored into an empty `chirpstack` with its row, the forwarder's folder restored in place.
  `systemctl` and `docker` lines not run (no systemd or Docker in it).
- **ChirpStack's LoRaWAN code on x86_64** (27 Oct): the fork's `lrwn` tests (181, and 8 in its docs: AES-256, the KDF,
  the MICs) pass in an emulated x86_64 Debian container with AES-NI, as on the Mac's arm64. The fork pins Rust 1.89.0
  (`rust-toolchain.toml`), so the image's compiler stays 1.89 whatever Rust image the Dockerfile starts from.
- **Steps 1 and 3 on Debian 13** (a `debian:trixie` container on the Mac, arm64 like the Pi; OpenSSL 3.5.7,
  Mosquitto 2.0.21; 26 Oct), from a copy of the committed tree: the broker started as cron starts it (a bare PATH), as
  a normal user, and printed each connection and message; `virtual_gateway.py --selftest` (step 7); ChirpStack's part
  played with its certificate. The lab's broker Pi is Debian 12 with mosquitto-oqs's Mosquitto instead: next item.
- **Step 3 on the lab's broker Pi** (27 Oct; Debian 12, mosquitto-oqs's Mosquitto 2.1.2 on its OpenSSL 3.6.3, the
  certificate from step 2 for 192.168.0.50): started with `broker.sh`; step 3's check from the Mac passed: X25519
  alone refused (`handshake failure`), X25519MLKEM768 negotiated, `Verification: OK` for the Pi's address. The
  same check against `openssl s_server` on the Mac also refuses an address not in the certificate.
- **Step 8 on Home Assistant 2026.10.4** (its container on the Mac, next to that broker; 26 Oct), from its default
  configuration, the steps as written (the MQTT form filled through the API the UI uses, the CA file uploaded the
  same way): it connected over TLS 1.3 with the login (the broker takes X25519MLKEM768 and ML-DSA-44 only), filled
  the three sensors from FPort 1 events, kept them on an FPort 2 event, and answered 20 of 20 FPort 1 events with
  "ack <FCnt>" on ChirpStack's command topic, 3.7 ms median (60 ms max) from event to command. After a broker
  restart it reconnected and kept answering. Without the restart after the integration, the automation stays
  unsubscribed (seen: hence the restart in step 8).
- **Step 5** on the Mac only (26 Oct): the setup into its own folder gives the same compose configuration as the
  running one (but for the project name), and the database dump restores into a fresh Postgres 14 with its 7 devices
  and frame counters.
- **The chain itself** (Pico → virtual gateway → Gateway Bridge → broker → ChirpStack → application and back): on
  the Mac with the broker on a Pi, 30 of 30 replies (Pico run 7), with `chirpstack_app.py` as the application.
