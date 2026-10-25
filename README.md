# IoT-PQC — ChirpStack with post-quantum TLS

**Branch `feature/custom-chirpstack-server`: the team's prototype.** Make your own branch from it for your part of the
work (`git switch -c <your-name>/<topic> feature/custom-chirpstack-server`). New to post-quantum TLS? Start with the
labs on `onboarding/learn`. Other branches: `macc-personal/test&implementation` (macc's own tests, same code; please
don't push there), `main` (the benchmark suite), `LoRa_1.1_implementation` (the LoRaWAN 1.1 chain with the stock
ChirpStack).

This branch builds the ChirpStack network server from our fork, so that it does post-quantum TLS itself:
TLS 1.3 with the hybrid key exchange X25519MLKEM768 and ML-DSA-44 certificates on both sides (mutual TLS). Its MQTT
integration connects straight to the project's MQTT broker on the Pi. Results: [docs/findings.md](docs/findings.md)
127-129.

## Done and left

Done (24 Oct):

- ChirpStack built from our fork does PQ mTLS to the Pi broker itself, checked with a downlink and a captured handshake
  (finding 128). The whole change is below.
- `gen_certs.sh --server-names` and `chirpstack_pq_setup.sh` with `CHIRPSTACK_IMAGE=`: the certificates and config
  for it.
- The Gateway Bridge does PQ mTLS when rebuilt with Go 1.27, no code change (finding 129); tested on the Mac only.

Left, to pick from (details and sub-tasks: [docs/pending.md](docs/pending.md)):

1. **The gateway:** the Gateway Bridge on the Pi with a Dockerfile in this repo, or a stand-in that turns the Pico's
   readings into LoRa frames.
2. **Uplinks through our ChirpStack** (needs 1).
3. **AES-256 LoRaWAN session keys in the fork** (finding 127): seven parts, from test vectors to the UI.
4. **The Pico W ↔ the Pi broker**, rerun on this branch.
5. **ChirpStack's gateway-side Mosquitto** still uses ECDSA P-256 / X25519.

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

## How the ChirpStack changes are made

Two ChirpStack programs are involved. **ChirpStack** itself (the network server, Rust) needed a code change, so it is
built from a fork. The **Gateway Bridge** (on the gateway, Go) needs no code change, only a newer Go to build it.

### The server's PQ TLS (done, findings 127-128)

How it was done:

1. **Find what does the TLS.** ChirpStack's two MQTT clients (its gateway backend and its integration) use rustls.
   rustls does no cryptography itself: a *provider* does. v4.19.2 uses the `ring` provider, which has no ML-KEM and no
   ML-DSA (finding 117). rustls 0.23.44 added ML-DSA certificates to its other provider, aws-lc-rs, which already had
   X25519MLKEM768.
2. **Check that nothing else needs changing.** Both clients build their settings with `ClientConfig::builder()`,
   which uses the process's default provider. The key loader passes the PKCS#8 key file through as it is, so OpenSSL's
   ML-DSA keys load unchanged.
3. **Fork, branch and edit.** Fork `chirpstack/chirpstack` and branch `iot-pqc` from the `v4.19.2` tag. Edit
   `Cargo.toml` and `main.rs` (the diff below), then run `cargo update -p rustls`: `Cargo.lock` moves to rustls 0.23.46
   and gains aws-lc-rs.
4. **Pin it here as a submodule:**
   `git submodule add -b iot-pqc https://github.com/cthyuiii/chirpstack.git network/chirpstack`. This repo records the
   exact fork commit it builds.
5. **Build an image.** The stock image copies in binaries built outside Docker. `scripts/chirpstack/Dockerfile`
   builds the UI (node 22) and the server (rust 1.89, plus cmake and clang for aws-lc-sys's C code) inside Docker,
   giving `iot-pqc/chirpstack:4.19.2-pq`.
6. **Certificates and config.**
   - `chirpstack_pq_setup.sh` with `CHIRPSTACK_IMAGE=` swaps that image in and points the integration at the broker,
     with the `chirpstack` ML-DSA-44 certificate.
   - rustls checks the broker's name, so `gen_certs.sh --server-names` reissues the broker's certificate for its
     address.
7. **Test.**
   - First, against a stand-in broker that accepts only X25519MLKEM768 and ML-DSA-44 client certificates. As a
     control, an X25519-only client was refused.
   - Then against the Pi broker: a downlink command was queued, and a capture showed X25519MLKEM768 (finding 128).

The whole change is one commit on the fork (`b4d894d1`): `Cargo.toml` + `chirpstack/src/main.rs` (+ `Cargo.lock`):

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
git clone --recurse-submodules -b feature/custom-chirpstack-server https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git
git submodule update --init                    # in an existing clone, after a checkout or pull
git -C network/chirpstack log --oneline -1     # the fork commit this branch builds
```

A ChirpStack change (e.g. AES-256) goes in the fork, on your own branch there, never on `iot-pqc` directly:

```bash
cd network/chirpstack
git switch -c <your-name>/<topic>              # from b4d894d1
# edit, build the image (Run it, below), test, then
git commit -am "..." && git push -u origin <your-name>/<topic>
cd ../.. && git add network/chirpstack && git commit -m "ChirpStack: <what changed>"   # the new pointer, on your branch here
```

### The gateway's PQ TLS (to do, finding 129)

The Gateway Bridge turns the packet forwarder's UDP (UDP over wifi for now as we don't have LoRa) into MQTT. The stock one is built with Go 1.26.5, which has
X25519MLKEM768 but no ML-DSA. That's why `setup_gateway_pi.sh` puts a Mosquitto bridge on the Pi in front of it today.

Go 1.27 adds ML-DSA to `crypto/x509` and `crypto/tls`. The Bridge only calls `tls.LoadX509KeyPair` with a default
`tls.Config`, so rebuilding it is enough: **no fork, no source change.** This build has been tested on the Mac, against
a stand-in broker. What's left:

1. **A Dockerfile in this repo** (e.g. `scripts/gateway-bridge/Dockerfile`), building a release tag of
   `chirpstack/chirpstack-gateway-bridge` with Go 1.27. The test built master `a5ae780` with this Dockerfile, from a
   clone of the Bridge (`docker build -f <this file> -t iot-pqc/gateway-bridge <clone>`):

   ```dockerfile
   FROM golang:1.27-alpine AS build
   WORKDIR /src
   COPY . .
   RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /gwb cmd/chirpstack-gateway-bridge/main.go
   FROM alpine:3.24.1
   RUN apk --no-cache add ca-certificates
   COPY --from=build /gwb /usr/bin/chirpstack-gateway-bridge
   USER nobody:nogroup
   ENTRYPOINT ["/usr/bin/chirpstack-gateway-bridge"]
   ```

   `go.mod` can stay at go 1.25: ML-DSA is offered either way.
2. **The key in seed-only form.** Go 1.27 refuses OpenSSL's default ML-DSA key file, which holds the seed and the
   expanded key. This rewrites the same key pair from its 32-byte seed; the certificate stays as it is:

   ```bash
   "$OSSL" pkey -provparam ml-dsa.output_formats=seed-only -in gateway.key -out gateway.seed.key
   ```

3. **Its config: MQTT straight to a PQ broker**, with a `gateway` certificate from that broker's client CA:

   ```toml
   [integration.mqtt.auth.generic]
   servers=["ssl://<broker host>:<port>"]
   ca_cert="/etc/chirpstack-gateway-bridge/tls/ca.crt"
   tls_cert="/etc/chirpstack-gateway-bridge/tls/gateway.crt"
   tls_key="/etc/chirpstack-gateway-bridge/tls/gateway.seed.key"
   ```

4. **Decide where it connects:**
   - **ChirpStack's PQ door on the Mac** (:8883; `chirpstack_pq_setup.sh` already makes its `gateway` certificate and
     ACL). Then the Pi's Mosquitto bridge goes.
   - **Or the Pi's central broker.** Then ChirpStack's gateway backend (`region_*.toml`) connects there too, and
     ChirpStack's own Mosquitto goes (item 5 in Done and left).
5. **Run it on the Pi** (arm64, the same Dockerfile). Feed it from `virtual_gateway.py` or a real packet forwarder on
   UDP 1700, then send uplinks through to ChirpStack.

### The server's AES-256 LoRaWAN (only thing that needs a code change)

This also goes in the fork, on its own branch from `iot-pqc` (see the commands above). The plan:

- **Pick the cipher by key length:** 16 bytes means AES-128 and 32 bytes means AES-256, so existing devices keep
  working. All four LoRaWAN 1.1 session keys are 32 bytes. ABP comes first, the OTAA join later.
- **The gateway and the radio need no change.** AES's block is 16 bytes at any key length, so the frame keeps its size
  and its 4-byte MIC.
- **Where the code changes:**
  - `lrwn`, ChirpStack's LoRaWAN library: `AES128Key` appears 297 times in 35 files;
  - the uplink and downlink paths;
  - the API and UI key fields (`AesKeyInput.tsx`).
- **The device side** (`lorawan11_256` on the Pico and the host) moves to four independent 32-byte keys.

The seven parts, from test vectors to the end-to-end test, are in [docs/pending.md](docs/pending.md).

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
