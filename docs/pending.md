# Pending: LoRa_1.1_implementation

What this branch still needs: a simulated ChirpStack network (no radio) that accepts our LoRaWAN 1.1 frames,
with 256-bit protection end to end and PQ TLS on every network link. How to run it: README section 0.4.
Results: docs/findings.md 115-119.
Chain: device ─ air ─► gateway ─ stunnel ═PQ═► ChirpStack ─ stunnel ═PQ═► MQTT broker ═PQ═► application.
Labels: **G&B** = Gateway & Backend, **B&R** = Benchmarking & Reproducibility.

## Still to do

- [~] **The two-machine run (steps 6, 10, 15):** ran 9 Oct (finding 119): 10 + 60 uplinks accepted. Left: the
  delay summary per device from `results/chirpstack_delay_pi_pq.csv`, and the 10 ms de-duplication run. Was: Mac: done (ChirpStack's stunnel already reaches the Pi's broker,
  finding 119); rsync `ca.crt`, `gateway.crt`, `gateway.key` to the Pi. Pi: `--serve-broker`, `PQ=~/chirpstack-pq
  setup_gateway_pi.sh`, `virtual_gateway.py --air`, the application on :18835; Mac: the device with `AIR=1` (README
  section 0.4). Then ChirpStack's delay at the default `deduplication_delay` and at 10 ms.
- [x] **Step 7, the Pico W as the device:** ran 9 Oct, `OK (15 MQTT blocks)`, 60 uplinks accepted (finding 119). To
  get its UDP send time (`air_us`), run it again on the new build. Was: register a second device (DevAddr 01234568, same profile, keys from
  `APP_KEYS`), then `AIR=<pi-ip>:1680 APP_KEYS=... DEV_ADDR=01234568 python3 pico/run_benchmarks.py --test mqtt --match
  chirpstack --tag chirpstack`. Compiled; not run on the board. It doesn't listen for downlinks (the host device does).
- [ ] **Inner integrity of `lorawan11_e2e`:** none now (the application trusts ChirpStack's MIC check and the link
  from ChirpStack), or a truncated AES-256-CMAC tag inside the payload (4 B: a 47-byte reading). Undecided.
- [ ] **256-bit key derivation** (G&B with Security & Key Management): how the 32-byte e2e key is derived and from what
  root, e.g. HKDF-SHA-256 (RFC 5869) or SP 800-108 with AES-256-CMAC, from a 256-bit device root key; inputs: DevAddr
  (ABP) or JoinNonce | JoinEUI | DevNonce (OTAA); a label and version. The root key lives on the device and with the
  application, never in ChirpStack. Proposal, not decided: refresh it with one ML-KEM ciphertext uplink (the device
  holds the backend's ML-KEM public key, installed like our trust anchor; ML-KEM-512: 768 B = 16 frames at DR0).
- [ ] `lorawan11_256` (the ad hoc nwk‖nwk2 / nwk2‖nwk CMAC keys): kept as the comparison row; ChirpStack rejects it.
- [ ] **ChirpStack hardening** (docs/findings.md, Hardening): the broker now needs a client certificate on the LAN
  (finding 118); still the compose defaults: the UI's admin password and `[api] secret`; certificate keys are mode
  644 for the containers.
- [ ] Step 12, the OTAA join (KIV), with the derivation above.

## Decided (9 Oct 2026)

- 256-bit: ChirpStack stays stock. The LoRaWAN layer stays standard (AES-128), and an AES-256 layer inside the
  payload passes through ChirpStack untouched; only the application decrypts it (option B, `lorawan11_e2e`).
- Test ChirpStack's own TLS (done: finding 117), define a 256-bit key derivation, report the delay ChirpStack adds.

## Steps

Machines: **Mac** = ChirpStack, Postgres, Redis and ChirpStack's Mosquitto (on 1884: the Mac's own Mosquitto has 1883).
**Pi 4** = our PQ broker (`--serve-broker`, as for the Pico), the virtual gateway and the Gateway Bridge (UDP 1700 stays
inside the Pi, as on a real gateway). **Device** = the Mac host client, or the Pico W.

1. [x] ChirpStack 4.19.2 on the Mac (chirpstack-docker), Gateway Bridge on the Pi (`scripts/setup_gateway_pi.sh`). 9 Oct.
2. [x] Virtual gateway `network/virtual_gateway.py` (stdlib, Semtech UDP; `--gap`, default 1 s). `--selftest`; a
   stand-in bridge; then the real one on the Pi (step 3) and on the Mac (finding 116).
3. [x] Smoke test: three LoRaWAN 1.1 uplinks with test keys (DevAddr 01234567; AppSKey 11..11, FNwkSIntKey 22..22,
   SNwkSIntKey 33..33, NwkSEncKey 44..44), all decrypted by ChirpStack byte for byte (finding 115). Run 1 lost FCnt 1:
   frames sent within 1 ms race in ChirpStack, hence `--gap`.
4. [x] One fixed device on the host client: `DEV_ADDR` (+ `APP_KEYS`), the FCnt reserved 64 ahead in
   `~/.cache/iot-pqc/fcnt_<DEV_ADDR>` (`FCNT_FILE`) under a lock. Tested on the Mac: a second process went on at 65
   after the first reserved 1-64; the frames for FCnt 1-3 equal step 3's byte for byte.
5. [x] Frames out of the broker: watch mode `RAW=1` ("<time> <topic> <hex>"), piped into the virtual gateway. Tested.
6. [~] The host client through ChirpStack: on one Mac, `lorawan11` FCnt 11-13 and `lorawan11_e2e` FCnt 75-77, all
   readings in order (finding 116). Two-machine run: still to do (above).
7. [~] The Pico W as the device: `-DMT_LORA_FIXED` (keys and DevAddr from the build, FCnt in LittleFS, pipeline
   `lorawan11` + `lorawan11_e2e`), runner entry "MQTT ChirpStack device ML-DSA-44". Compiled; board run still to do.
8. [x] `lorawan11_e2e` (option B): `app_aead.c` and `lora_aead.h` (FPort 2; e2e key = `APP_KEYS` bytes 64-95; the
   AppSKey stays bytes 0-15, so ChirpStack holds one AppSKey for both schemes); self-test; `aead_host_test` 88 / 88 frames
   identical; `chirpstack_app.py` removes the layer (its self-test decrypts a C-made frame with the `openssl`
   command). Through ChirpStack on the Mac: 3 / 3 readings (finding 116). Now in the pipeline's defaults.
9. [x] ChirpStack's TLS: `scripts/chirpstack_tls_test.sh`, 7 set-ups (finding 117): neither client does ML-DSA,
   ChirpStack not even the hybrid key exchange. Worked around in steps 13-14.
10. [~] ChirpStack's delay: `chirpstack_app.py --sent`. One Mac: median 220.3 ms at the default de-duplication wait,
    29.5 ms at 10 ms (finding 116). Two-machine run: still to do (above).
11. [x] Downlinks: a downlink queued in ChirpStack went out after the next uplink → bridge → virtual gateway →
    `PUB=pqc/down` relay → the device's watcher verified its 1.1 MIC and decrypted it (finding 116).
12. [ ] OTAA join (KIV).
13. [x] stunnel, a TLS proxy (`scripts/stunnel`: Alpine 3.23, OpenSSL 3.5.8), in front of the Gateway Bridge
    (`PQ=... setup_gateway_pi.sh`) and of ChirpStack (a container in its compose network): both speak plain MQTT only
    on their own machine; on the network TLS 1.3, X25519MLKEM768, ML-DSA-44 client certificates (finding 118).
14. [x] PQ on both sides of ChirpStack (`scripts/chirpstack_pq_setup.sh`), as required: gateway → stunnel →
    ChirpStack's Mosquitto (8883: ML-DSA-44 CA, X25519MLKEM768 only, client certificate required; plain only on
    127.0.0.1:1884) → ChirpStack → stunnel → the project's PQ MQTT broker (:18835) → application. Classical and
    certificate-less clients refused (finding 118); the whole chain with downlinks on the Mac (finding 119).
15. [x] (Pico W and Mac device through the Pi, finding 119; send timing `send_us` / `air_us` and the computed
    LoRa airtime per frame added after.) The radio as UDP "air": `virtual_gateway.py --air`, the device `mqtt_tls_timer AIR=1` (+ `AIR_LISTEN` for
    downlinks, sent back to where the uplink came from), the Pico `AIR=` at build time (compiled). Tested on the Mac
    with the full PQ chain (finding 118).
