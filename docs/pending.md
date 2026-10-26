# Pending: custom ChirpStack server

What this branch needs: ChirpStack built from our fork, doing PQ TLS itself (TLS 1.3, X25519MLKEM768, ML-DSA-44
certificates, mTLS) on every MQTT link, then AES-256 LoRaWAN session keys. How to run it: README. Results:
docs/findings.md 127-129. Earlier steps (the stock ChirpStack chain): `testing/lorawan11-stock-chirpstack`'s pending.md.

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

1. [ ] **The gateway:** the Gateway Bridge (Go 1.27, seed-only key) on the Pi, its Dockerfile in the repo, built from a
   release tag; or a stand-in that turns the Pico's readings into LoRa frames. To decide.
2. [ ] **Uplinks through our ChirpStack** (needs 1): ChirpStack takes them only as gateway events.
3. [ ] **AES-256 LoRaWAN in the fork** (finding 127; ABP first; cipher by key length, so 16-byte keys stay AES-128):
   - spec + test vectors (1.1 uplink / downlink MIC, FRMPayload, FOpts at 32 bytes)
   - `lrwn`: the key type takes 16 or 32 bytes; AES / CMAC helpers; constant-time MIC compares
   - ChirpStack: session, uplink and downlink paths (storage needs no schema change)
   - API + UI (`AesKeyInput.tsx`: 32 or 64 hex)
   - fork / build / image
   - Pico + host `lorawan11_256`: four independent 32-byte session keys (today two 16-byte keys joined)
   - end-to-end test, benchmarks, docs
4. [ ] **The Pico W ↔ the Pi broker, rerun on this branch** (`--test mqtt --match 'tls ml-dsa-44'`).
5. [ ] **ChirpStack's gateway-side hop:** its own Mosquitto still uses ECDSA P-256 / X25519. Our build can do ML-DSA
   there, or the hop goes if the gateway connects to the central broker.

## Paused / KIV

- ACL and CRL on the broker (`BROKER_ACL=1`, `BROKER_CRL=1`): off for now.
- TLS 1.3 only inside the fork (`builder_with_protocol_versions`): the broker already refuses TLS 1.2.
- `run_all.sh`: still lists the removed stages; `docs/how_it_works.md` describes main's full suite.
- ChirpStack's UI on plain HTTP (:8080, the Mac only).
- OTAA join; a real radio and packet forwarder.
