# IoT-PQC — ChirpStack with post-quantum TLS

**Branch `macc-personal/test&implementation`: macc's own test and implementation branch.** Please don't push here.
Teammates work from `feature/custom-chirpstack-server` (same starting point) on their own branches. The benchmark suite
is on `main`, the LoRaWAN 1.1 simulation chain on `LoRa_1.1_implementation`.

This branch builds the ChirpStack network server from our fork, so that it does post-quantum TLS itself:
TLS 1.3 with the hybrid key exchange X25519MLKEM768 and ML-DSA-44 certificates on both sides (mutual TLS). Its MQTT
integration connects straight to the project's MQTT broker on the Pi. What is done and what is left:
[docs/pending.md](docs/pending.md). Results: [docs/findings.md](docs/findings.md) 127-129.

## What runs

```text
Now (finding 128):

Pico W ═PQ═► MQTT broker ◄═PQ═ ChirpStack (our build)
(Wi-Fi)      (Pi, :18835,       (Mac, Docker: chirpstack, postgres, redis, and its own Mosquitto
              run_all.sh         for the gateway topics, which nothing feeds while the gateway is paused)
              --serve-broker)
                  ▲
                  ╚═PQ═ application (chirpstack_app.py / mosquitto_pub, `application` certificate)

Next: LoRa device ─radio─► gateway (packet forwarder + Gateway Bridge on Go 1.27) ═PQ═► MQTT broker

═PQ═  TLS 1.3, X25519MLKEM768, ML-DSA-44 certificates, a client certificate required (mTLS)
```

- ChirpStack ↔ the Pi broker: verified on the Pi (192.168.50.133) with a downlink command and a captured handshake
  (finding 128).
- The Pico W ↔ the Pi broker: run on the earlier branches; not rerun on this one yet.
- The Gateway Bridge on Go 1.27: tested on the Mac against a stand-in broker only (finding 129). Its Dockerfile is not
  in the repo yet.

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
├── docs/  findings.md (127-129: ChirpStack), pending.md (done / left), how_it_works.md (written for main's full
│          suite: parts describe files removed here)
├── scripts/
│   ├── chirpstack/Dockerfile   ← our ChirpStack image: UI (node 22) → server (rust 1.89) → debian-slim
│   ├── chirpstack_pq_setup.sh  ← Mac: ChirpStack's certificates and config (docker-compose.override.yml);
│   │                             CHIRPSTACK_IMAGE= runs our image and points its integration at the broker
│   ├── gen_certs.sh            ← CA, server and client certificates per signature → certs/<SIG>/;
│   │                             --server-names: reissue a set's server.crt for the broker's address
│   ├── setup_gateway_pi.sh     ← Pi: the stock Gateway Bridge + its Mosquitto bridge (the gateway path, paused)
│   ├── chirpstack_tls_test.sh  ← what the stock ChirpStack / Gateway Bridge MQTT clients can do (finding 117)
│   └── collate_results.py      ← result files → results/all_results.csv
├── network/
│   ├── chirpstack/             ← the ChirpStack fork (submodule)
│   ├── mqtt_bench.py           ← the broker (one Mosquitto per certificate type) and the host benches' driver
│   ├── mqtt_tls_timer.c        ← MQTT client over TLS / mTLS (OpenSSL), the LoRaWAN pipeline, raw frames, downlinks
│   ├── app_aead.{c,h}          ← LoRaWAN 1.0.x / 1.1 frames, the 256-bit layer inside them (lorawan11_e2e)
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

# Mac: our ChirpStack image (the first build takes a while; later ones reuse the Rust cache)
git submodule update --init
docker build -f scripts/chirpstack/Dockerfile -t iot-pqc/chirpstack:4.19.2-pq network/chirpstack

# Mac: ChirpStack's compose files (outside iCloud), then our certificates and config on top
git clone https://github.com/chirpstack/chirpstack-docker.git ~/chirpstack-docker
CHIRPSTACK_IMAGE=iot-pqc/chirpstack:4.19.2-pq bash scripts/chirpstack_pq_setup.sh <mac-ip> <pi-ip>:18835

# Mac: certs/ to the Pi, without the CA keys (this also carries the `application` certificate)
X=(--exclude CA.key --exclude ClientCA.key --exclude update.key --exclude '*.srl' --exclude chirpstack.key)
rsync -a --delete --delete-excluded "${X[@]}" certs/ <pi-user>@<pi-ip>:<pi-repo>/certs/

# Pi, repo root, its own terminal: the broker (prints one line per connection: client, certificate, TLS / mTLS)
./run_all.sh --serve-broker

# Mac: start ChirpStack (the door mosquitto-pq is for the gateway path only: leave it out while that is paused)
(cd ~/chirpstack-docker && docker compose up -d --remove-orphans postgres redis mosquitto chirpstack)
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

**The Pico W against the Pi broker** (Mac, the Pico plugged in; the certificates are built into the firmware):

```bash
export WIFI_SSID="<your SSID>"; read -rs WIFI_PASS; export WIFI_PASS   # typed, so the password stays out of history
BROKER=<pi-ip> python3 pico/run_benchmarks.py --test mqtt --match 'tls ml-dsa-44'
```

**The Gateway Bridge's key** (Go 1.27, finding 129): Go reads ML-DSA private keys only in the seed-only form. Same
key pair, the certificate unchanged:

```bash
"$OSSL" pkey -provparam ml-dsa.output_formats=seed-only -in gateway.key -out gateway.seed.key
```

## Tests

```bash
bash pico/tests/aead_host_test/run.sh          # the Pico's LoRaWAN / AES / Ascon code = the host's, frame for frame
bash pico/tests/deploy_host_test/run.sh        # the deployment firmware's checks (not used on this branch)
python3 pico/tests/mqtt_parse_test.py          # Pico log → results CSV
python3 network/virtual_gateway.py --selftest
python3 network/chirpstack_app.py --selftest
```
