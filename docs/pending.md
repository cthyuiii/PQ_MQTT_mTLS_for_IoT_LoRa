# Pending: custom ChirpStack server

What this branch needs: ChirpStack built from our fork, doing PQ TLS itself (TLS 1.3, X25519MLKEM768, ML-DSA-44
certificates, mTLS) on every MQTT link, then AES-256 LoRaWAN session keys. How to run it: README. Results:
docs/findings.md 127-129. Earlier steps (the stock ChirpStack chain): `LoRa_1.1_implementation`'s pending.md.

Machines: **Mac** = ChirpStack in Docker and the certificates (CA keys stay here). **Pi 4** (192.168.50.133) = the MQTT
broker (`./run_all.sh --serve-broker`, :18835). **Device** = the Pico W.

## Done

- [x] **ChirpStack does PQ mTLS itself** (24 Oct, finding 128): the fork `cthyuiii/chirpstack` (`iot-pqc`, commit
  `b4d894d1`: rustls on aws-lc-rs) as the submodule `network/chirpstack`, built by `scripts/chirpstack/Dockerfile`.
  Its integration connected straight to the Pi broker; a downlink command from the Pi was queued; the captured
  handshake used X25519MLKEM768, both sides ML-DSA-44. Run with `chirpstack_pq_setup.sh` (`CHIRPSTACK_IMAGE=`).
- [x] **`gen_certs.sh --server-names`** (24 Oct): reissues a set's `server.crt` for the broker's address (rustls checks
  it). Used for MLDSA44 with `IP:192.168.50.133`.
- [x] **`chirpstack_pq_setup.sh` with `CHIRPSTACK_IMAGE`** (24 Oct): our image, integration to the broker, no door
  bridge. Without it the output is byte-identical to before (checked).
- [x] **The branch stripped to the MQTT path** (24 Oct, `12bbba0c`): the signature benches (Pico sketches and
  `signatures/`, incl. the NIST reference code), `liboqs_bench`, the KEM / SNOVA host tests and the QEMU test removed.
- [x] **The Gateway Bridge on Go 1.27** (24 Oct, finding 129): PQ mTLS with no code change, the key in seed-only form.
  Tested on the Mac against a stand-in broker only.

## Next

1. [ ] **The gateway** (25 Oct: it shares a machine with ChirpStack, a Pi 5 later; one PQ broker on another machine
   for the gateway, ChirpStack and the application):
   - [x] `scripts/gateway-bridge/Dockerfile`: v4.1.2, unchanged, built with Go 1.27 (22 s on the Mac).
   - [x] `chirpstack_pq_setup.sh` `GATEWAY_IMAGE=`: the Bridge as a compose service (UDP 127.0.0.1:1700), ML-DSA-44
     mTLS to the broker as `gateway` (seed-only key); ChirpStack's gateway backend on the broker too. The broker's
     ACL (`BROKER_ACL=1`) has the gateway topics. Without `GATEWAY_IMAGE` the output is byte-identical (checked).
   - [x] The Bridge ↔ the Pi broker, from the Mac (a separate compose project, an unregistered gateway ID): a frame on
     UDP 1700 arrived on the broker as the gateway's uplink event.
   - [ ] The main setup: uplinks through ChirpStack (README, "Check the gateway path").
   - [ ] The radio: a Pi 5 with the SX1303 HAT and Semtech's packet forwarder (docs/radio_gateway.md); both images
     built on that Pi 5 (arm64).
2. [ ] **Uplinks through our ChirpStack** (needs 1): ChirpStack takes them only as gateway events.
3. [ ] **AES-256 LoRaWAN** (finding 127): every key 32 bytes; 1.0.3, 1.0.4 and 1.1, ABP and OTAA. The plan, the
   rules and the vectors: `docs/aes256_lorawan.md`.
   - [x] rules + test vectors V1-V10 (25 Oct): `scripts/aes256_vectors.sh`, openssl only, five controls pass; the same
     output on OpenSSL 3.5, 3.6 and 4.0
   - [x] `lrwn` (a folder in our ChirpStack fork): 32-byte key type, AES-256 / AES-256-CMAC, the KDF, constant-time
     MIC compares; V1-V10 as tests (25 Oct, uncommitted in `network/chirpstack`)
   - [x] the rest of the fork: KEKs, the API and UI (64 hex characters), its 215 tests; the image
     `iot-pqc/chirpstack:4.19.2-pq-aes256` (25 Oct)
   - [x] host tool (`app_aead.c`, `mqtt_tls_timer AIR=1`, 26 Oct): 32-byte keys, 1.0.x and 1.1 frames, OTAA, the
     1.0.3 / 1.0.4 / 1.1 DevNonce; its self-test reproduces V1, V3, V5-V10; the Pico's `lora_aead.h` the same keys.
     Tested against an openssl stand-in for ChirpStack (docs/aes256_lorawan.md), not yet against ChirpStack
   - [ ] end to end, six cases (1.0.3, 1.0.4, 1.1 × ABP, OTAA): host tool → virtual gateway → ChirpStack → broker → app
   - [ ] the Pico on the radio: LoRaMac-node v4.7.0 fork (secure element), Arm's Pico port moved to v4.7.0, an SX1262
     board file
4. [ ] **The Pico W ↔ the Pi broker, rerun on this branch** (`--test mqtt --match 'tls ml-dsa-44'`).
5. [ ] **ChirpStack's gateway-side hop:** with `GATEWAY_IMAGE` it goes: the gateway backend uses the PQ broker, and
   ChirpStack's own Mosquitto and the door are unused. Remove them once item 1 runs.

## Paused / KIV

- ACL and CRL on the broker (`BROKER_ACL=1`, `BROKER_CRL=1`): off for now.
- TLS 1.3 only inside the fork (`builder_with_protocol_versions`): the broker already refuses TLS 1.2.
- `run_all.sh`: still lists the removed stages; `docs/how_it_works.md` describes the full suite (`testing/benchmarks`).
- ChirpStack's UI on plain HTTP (:8080, the Mac only).
