# IoT-PQC — ChirpStack with post-quantum TLS

**Branch `macc-personal/test&implementation`: macc's own test and implementation branch.** Please don't push here.
Teammates work from `feature/custom-chirpstack-server` (same starting point) on their own branches. The benchmark suite
is on `testing/benchmarks`, the LoRaWAN 1.1 simulation chain on `LoRa_1.1_implementation`.

This branch builds the ChirpStack network server from our fork, so that it does post-quantum TLS itself:
TLS 1.3 with the hybrid key exchange X25519MLKEM768 and ML-DSA-44 certificates on both sides (mutual TLS). Its MQTT
integration connects straight to the project's MQTT broker on the Pi. The Gateway Bridge, rebuilt with Go 1.27, runs
next to it, and both reach the gateway's messages through that same broker. What is done and what is left:
[docs/pending.md](docs/pending.md). Results: [docs/findings.md](docs/findings.md) 127-129.

## What runs

```text
Machine 1 (the Mac now, a Pi 5 later), in Docker:

  packet forwarder ─UDP─► Gateway Bridge (Go 1.27) ══PQ══╗       ╔══PQ══ ChirpStack (our build): its gateway
  (virtual_gateway.py for now; the UDP                   ║       ║       backend and its integration
   never leaves the machine)                             ║       ║
                                                         ▼       ▼
Machine 2 (the Pi 4 now, a second Pi 5 later):        MQTT broker (:18835, run_all.sh --serve-broker)
                                                         ▲       ▲
  Pico W (Wi-Fi) ═PQ═════════════════════════════════════╝       ╚══PQ══ application (chirpstack_app.py / mosquitto_pub)

═PQ═  TLS 1.3, X25519MLKEM768, ML-DSA-44 certificates, a client certificate required (mTLS)
```

- ChirpStack's integration ↔ the Pi broker: verified on the Pi (192.168.50.133) with a downlink command and a captured
  handshake (finding 128).
- The Gateway Bridge (v4.1.2 on Go 1.27) ↔ the Pi broker: tested from the Mac on 25 Oct, in a separate compose project
  with an unregistered gateway ID. A frame sent to its UDP port arrived on the Pi broker as the gateway's uplink event,
  along with its stats and connection state.
- ChirpStack's gateway backend ↔ the Pi broker: set up by `chirpstack_pq_setup.sh`, not run yet.
- The Pico W ↔ the Pi broker: run on the earlier branches; not rerun on this one yet.
- The radio: none yet. How to set up the gateway's radio (a Pi 5 with the SX1303 HAT):
  [docs/radio_gateway.md](docs/radio_gateway.md).

## What changed in ChirpStack

ChirpStack v4.19.2 is a git submodule at `network/chirpstack`: our fork `cthyuiii/chirpstack`, branch `iot-pqc`,
pinned at commit `b4d894d1`. The whole change is one commit, `Cargo.toml` + `chirpstack/src/main.rs` (+ `Cargo.lock`):

```diff
# Cargo.toml (the workspace's rustls)
-    rustls = { version = "0.23", default-features = false, features = [
+    rustls = { version = "0.23.44", default-features = false, features = [
       "logging",
       "std",
       "tls12",
-      "ring",
+      "aws_lc_rs",
+      "prefer-post-quantum",
     ] }

# chirpstack/src/main.rs, first lines of main()
+    // aws-lc-rs: X25519MLKEM768 first and ML-DSA certificates (rustls >= 0.23.44); ring is still linked
+    // through reqwest and lapin, so the process default is chosen here
+    rustls::crypto::aws_lc_rs::default_provider()
+        .install_default()
+        .expect("install the aws-lc-rs crypto provider");
```

- **`ring` → `aws_lc_rs`:** rustls does no cryptography itself; a provider does. ring has no ML-KEM or ML-DSA,
  aws-lc-rs (AWS's libcrypto) has both. Nothing post-quantum is written by us: it all comes from aws-lc-rs.
- **`prefer-post-quantum`:** X25519MLKEM768 goes first in the ClientHello. With `default-features = false` it has to be
  named.
- **`0.23.44`:** the lowest rustls with ML-DSA certificates on aws-lc-rs. `Cargo.lock` resolves it to 0.23.46
  (rustls-webpki 0.103.16, aws-lc-rs 1.18.2, aws-lc-sys 0.46.0).
- **`install_default()`:** two of ChirpStack's dependencies (reqwest, lapin) still pull in ring, so two providers are
  compiled in and rustls won't guess which one to use. `main()` picks aws-lc-rs before anything opens a connection.
- **`tls12` stays:** hyper-rustls, futures-rustls and redis turn it on anyway. TLS 1.2 is never used here: the broker
  accepts TLS 1.3 only, and X25519MLKEM768 / ML-DSA exist only in TLS 1.3.

On this branch the fork also does AES-256 LoRaWAN (`docs/aes256_lorawan.md`): every key is 32 bytes (64 hex
characters in the API and UI), every MIC and encryption AES-256 / AES-256-CMAC, for 1.0.x and 1.1, ABP and OTAA. Most
of it is in `lrwn` (`aes256.rs`, `keys.rs`'s `kdf()`, `phy_payload.rs`). It takes AES-256 devices only; its image is
`iot-pqc/chirpstack:4.19.2-pq-aes256`. The test device without a radio, `mqtt_tls_timer` with `AIR=1` (`app_aead.c`),
does the same: ABP, and OTAA (`OTAA=1.0.3`, `1.0.4` or `1.1`).

Working with the submodule:

```bash
git clone --recurse-submodules -b 'macc-personal/test&implementation' https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git
git submodule update --init                    # in an existing clone, after a checkout or pull
# a ChirpStack change: commit and push inside network/chirpstack (the fork), then commit the new pointer here
git -C network/chirpstack log --oneline -1     # the fork commit this branch builds
```

## Files

```text
├── run_all.sh                  ← on this branch only --serve-broker is used (the Pi's MQTT broker); its other stages
│                                 still refer to files removed here (signatures/, tls_sweep.sh, build_wolfssl.sh)
├── docs/  findings.md (127-129: ChirpStack), pending.md (done / left), radio_gateway.md (the Pi 5's radio),
│          aes256_lorawan.md (the AES-256 LoRaWAN plan, rules and test vectors), how_it_works.md (written for the full
│          benchmark suite on `testing/benchmarks`: parts describe files removed here)
├── scripts/
│   ├── chirpstack/Dockerfile   ← our ChirpStack image: UI (node 22) → server (rust 1.89) → debian-slim
│   ├── gateway-bridge/Dockerfile ← the Gateway Bridge v4.1.2, unchanged, built with Go 1.27 (ML-DSA)
│   ├── chirpstack_pq_setup.sh  ← machine 1: ChirpStack's certificates and config (docker-compose.override.yml);
│   │                             CHIRPSTACK_IMAGE= runs our image and points its integration at the broker;
│   │                             GATEWAY_IMAGE= adds the Go 1.27 Gateway Bridge; it and ChirpStack's gateway
│   │                             backend then use the broker too
│   ├── gen_certs.sh            ← CA, server and client certificates per signature → certs/<SIG>/;
│   │                             --server-names: reissue a set's server.crt for the broker's address
│   ├── setup_gateway_pi.sh     ← a gateway on its own Pi: the stock Gateway Bridge + a Mosquitto bridge (not used
│   │                             now that the gateway shares machine 1)
│   ├── chirpstack_tls_test.sh  ← what the stock ChirpStack / Gateway Bridge MQTT clients can do (finding 117)
│   ├── aes256_vectors.sh       ← AES-256 LoRaWAN test vectors (1.0.x, 1.1, ABP, OTAA) with the openssl command line
│   └── collate_results.py      ← result files → results/all_results.csv
├── network/
│   ├── chirpstack/             ← the ChirpStack fork (submodule)
│   ├── mqtt_bench.py           ← the broker (one Mosquitto per certificate type) and the host benches' driver
│   ├── mqtt_tls_timer.c        ← MQTT client over TLS / mTLS (OpenSSL), the LoRaWAN pipeline, raw frames, downlinks;
│   │                             AIR=1: the test device (ABP, or an OTAA join first)
│   ├── app_aead.{c,h}          ← AES-256 LoRaWAN 1.0.x / 1.1 frames and joins, the 256-bit layer inside (lorawan11_e2e)
│   ├── chirpstack_app.py       ← the application behind ChirpStack: opens the 256-bit layer, replies
│   ├── virtual_gateway.py      ← stand-in LoRa gateway (Semtech UDP), until a packet forwarder replaces it
│   └── broker_hs_timing.c, hs_timing_openssl.c, wire_stats.h, provenance.py, build_*.sh
├── pico/
│   ├── run_benchmarks.py       ← compile, flash, read serial; --test mqtt = the MQTT / TLS / mTLS runs
│   ├── sketches/mqtt_tls_bench ← the Pico W firmware: MQTT over TLS / mTLS (wolfSSL), lora_aead.h
│   ├── sketches/wolfssl_bench  ← make_wolfssl_lib.sh + wolfssl_user_settings.h: the wolfSSL library both sketches use
│   └── tests/                  ← aead_host_test, deploy_host_test, mqtt_parse_test.py
└── certs/  results/            ← made by the runs (gitignored)
```

## Run it

Mac = ChirpStack (Docker Desktop) and the certificates; Pi = the MQTT broker. Certificates are made on the Mac only,
which keeps the CA keys.

```bash
# Mac, repo root. OpenSSL 3.5+ (not Apple's /usr/bin/openssl, which is LibreSSL)
export OSSL=/opt/homebrew/opt/openssl@3/bin/openssl
bash scripts/gen_certs.sh                                        # certs/<SIG>/, incl. MLDSA44 (the broker's set)
bash scripts/gen_certs.sh --server-names MLDSA44 IP:<pi-ip>      # rustls checks the broker's name; same CA and key

# Mac: our ChirpStack image (the first build takes a while; later ones reuse the Rust cache), and the Gateway Bridge's
git submodule update --init
docker build -f scripts/chirpstack/Dockerfile -t iot-pqc/chirpstack:4.19.2-pq-aes256 network/chirpstack
docker build -t iot-pqc/gateway-bridge:4.1.2-go1.27 scripts/gateway-bridge

# Mac: ChirpStack's compose files (outside iCloud), then our certificates and config on top
git clone https://github.com/chirpstack/chirpstack-docker.git ~/chirpstack-docker
# (GATEWAY_IMAGE: also the gateway's key in seed-only form, gateway.seed.key, the only form Go 1.27 reads)
CHIRPSTACK_IMAGE=iot-pqc/chirpstack:4.19.2-pq-aes256 GATEWAY_IMAGE=iot-pqc/gateway-bridge:4.1.2-go1.27 \
  bash scripts/chirpstack_pq_setup.sh <mac-ip> <pi-ip>:18835

# Mac: certs/ to the Pi, without the CA keys (this also carries the `application` certificate)
X=(--exclude CA.key --exclude ClientCA.key --exclude update.key --exclude '*.srl' --exclude chirpstack.key)
rsync -a --delete --delete-excluded "${X[@]}" certs/ <pi-user>@<pi-ip>:<pi-repo>/certs/

# Pi, repo root, its own terminal: the broker (prints one line per connection: client, certificate, TLS / mTLS)
./run_all.sh --serve-broker          # BROKER_ACL=1: per-role topics, incl. the gateway's (this branch's mqtt_bench.py)

# Mac: start ChirpStack and the Gateway Bridge (ChirpStack's own Mosquitto only because compose needs it to start)
(cd ~/chirpstack-docker && docker compose up -d --remove-orphans postgres redis mosquitto chirpstack gateway-bridge-pq)
```

`chirpstack_pq_setup.sh` only adds `docker-compose.override.yml` and new files to `~/chirpstack-docker`;
`rm docker-compose.override.yml && docker compose up -d --remove-orphans` goes back to the stock setup.

**Check it:**

```bash
# Mac: ChirpStack's log, no TLS errors; the Pi's broker prints a line for `chirpstack` over mTLS
(cd ~/chirpstack-docker && docker compose logs chirpstack | grep -i -E 'mqtt|error|warn')
# Pi: a downlink command as the application (a device must exist in ChirpStack); it shows in the device's queue
C=certs/MLDSA44
mosquitto_pub -h localhost -p 18835 --cafile $C/CA.crt --cert $C/application.crt --key $C/application.key \
  -t application/<app id>/device/<DevEUI>/command/down -m '{"devEui":"<DevEUI>","fPort":1,"data":"AQ=="}'
# Mac: the handshake on the wire (Wireshark: ClientHello key share X25519MLKEM768, 1,216 B)
sudo tcpdump -i en0 -s 0 -w hs.pcap 'tcp port 18835 and host <pi-ip>' &   # then restart chirpstack (compose restart)
```

**Check the gateway path** (a gateway `0102030405060708` registered in ChirpStack, and a device: below):

```bash
# Mac: the Bridge is connected, and ChirpStack's log has no MQTT errors
(cd ~/chirpstack-docker && docker compose logs gateway-bridge-pq | grep -i -E 'mqtt|error' | tail -3)
(cd ~/chirpstack-docker && docker compose logs chirpstack | grep -i -E 'mqtt|error|warn' | tail -5)
# Pi: watch the gateway's messages and ChirpStack's uplink events on the broker
C=certs/MLDSA44
mosquitto_sub -h localhost -p 18835 --cafile $C/CA.crt --cert $C/application.crt --key $C/application.key \
  -t 'as923/gateway/+/event/up' -t 'application/+/device/+/event/up' -v
# Mac, two terminals in network/: the stand-in gateway, then three uplinks from the device over the "air"
python3 virtual_gateway.py --air 127.0.0.1:1680
```

Each uplink shows twice on the Pi: once as the gateway's event, once as ChirpStack's decrypted event.

**The device, six ways.** In ChirpStack, a device profile per case (region AS923; MAC version 1.0.3, 1.0.4 or 1.1.0;
OTAA on or off) and a device on it; its keys are 64 hex characters. JOIN_EUI defaults to `0000000000000000`.

```bash
# Mac, network/. ABP 1.1, DevAddr 01234567: APP_KEYS = AppSKey | FNwkSIntKey | SNwkSIntKey (as in ChirpStack's
# activation; its NwkSEncKey is ChirpStack's only: this tool sends no MAC commands and doesn't read ChirpStack's)
K=$(python3 -c "print('11'*32+'22'*32+'33'*32)")
AIR=1 DEV_ADDR=01234567 APP_KEYS=$K AEAD=lorawan11_256 MSGS=3 AIR_LISTEN=5 ./mqtt_tls_timer 127.0.0.1 1680 1 0
# ABP 1.0.3 and 1.0.4 (the same frames; the profile tells them apart): AppSKey | NwkSKey | (unused)
AIR=1 DEV_ADDR=01234568 APP_KEYS=$K AEAD=aes256ctr MSGS=3 AIR_LISTEN=5 ./mqtt_tls_timer 127.0.0.1 1680 1 0
# OTAA 1.0.3 (random DevNonce) or 1.0.4 (0, 1, 2, ... in ~/.cache/iot-pqc/devnonce_<DevEUI>): the AppKey
OTAA=1.0.4 DEV_EUI=<DevEUI> APP_KEY=<64 hex> AIR=1 MSGS=3 AIR_LISTEN=5 ./mqtt_tls_timer 127.0.0.1 1680 1 0
# OTAA 1.1 (DevNonce counted as 1.0.4's): the NwkKey and the AppKey
OTAA=1.1 DEV_EUI=<DevEUI> NWK_KEY=<64 hex> APP_KEY=<64 hex> AIR=1 MSGS=3 AIR_LISTEN=5 ./mqtt_tls_timer 127.0.0.1 1680 1 0
```

With OTAA the first row is `join,<version>,<DevNonce>,<DevAddr>,<ms>`; `down,...` rows are downlinks (e.g. from
`chirpstack_app.py --reply`). A wrong key or profile ends with the reason (no join-accept; the other LoRaWAN version).

## Tests

```bash
bash pico/tests/aead_host_test/run.sh          # the Pico's LoRaWAN / AES / Ascon code = the host's, frame for frame
bash pico/tests/deploy_host_test/run.sh        # the deployment firmware's checks (not used on this branch)
python3 pico/tests/mqtt_parse_test.py          # Pico log → results CSV
AEAD=lorawan11_256 MSGS=1 AIR=1 network/mqtt_tls_timer 127.0.0.1 9 1 0   # its self-test (V1-V10 incl.), then 1 frame
python3 network/virtual_gateway.py --selftest
python3 network/chirpstack_app.py --selftest
```
