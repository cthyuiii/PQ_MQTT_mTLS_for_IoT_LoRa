# Pending: testing/lorawan11-stock-chirpstack

What this branch still needs: a simulated ChirpStack network (no radio) that accepts our LoRaWAN 1.1 frames,
with 256-bit protection end to end and PQ TLS on every network link. How to run it: README section 0.4.
Results: docs/findings.md 115-120.
Chain: device ─ air ─► gateway ─TLS─► bridge ═PQ═► door ─TLS─► ChirpStack ─TLS─► door ═PQ═► MQTT broker ═PQ═► application
(no plain MQTT; finding 125).
Labels: **G&B** = Gateway & Backend, **B&R** = Benchmarking & Reproducibility.

## Status: done (10 Oct 2026)

The chain works end to end with the Pico W (finding 119), with the final-setup hardening, the end-to-end tag and the
per-device keys in place (finding 120). Every item below is ticked; the rest is KIV.

- [x] **On the Pi:** certificates pushed without CA keys; the Pico's tagged run went through ChirpStack (60 uplinks,
  18:54-18:55 UTC, none rejected). Its timing is on the Pi (`results/*chirpstack*`).
- [x] **ChirpStack's admin password:** changed (10 Oct).
- [x] **The 256-bit key derivation** (finding 120): the application's master key (a file) → each device's end-to-end
  key = HKDF-SHA-256(master, "IoT-PQC lorawan11_e2e v1" | DevEUI); `chirpstack_app.py --e2e-master-file`, and
  `--derive <DevEUI>` for provisioning. To share with Security & Key Management.
- [x] **Merge:** no; the branch stays as it is (the LoRa deliverable).
- [x] **The Pi's broker with `BROKER_ACL=1`:** on since 10 Oct 04:32 UTC; anonymous refused on `application/`
  (finding 120).
- [x] **The Pico on a derived key** (10 Oct): its FPort 2 readings opened with the application's master key. 28
  uplinks got through, then a one-minute Pi ↔ Mac link drop lost the rest. The final run (04:39-04:40 UTC, ACL on):
  60 / 60 through ChirpStack, no errors, but on the old shared test key (finding 120). Both together: 12 Oct (121).
- [x] **The broker's CRL for device certificates** (12 Oct, finding 121): `gen_certs.sh --client-crl`,
  `BROKER_CRL=1`; revoked device refused on the Mac, +80 µs per handshake there; on at the Pi's broker since the 12 Oct
  run (no frame rejected).
- [x] **The device without TLS** (12-13 Oct, finding 123): the ChirpStack firmware makes no broker connection (mode
  `air`: seal, open, send over the air); mTLS starts at the gateway. Run on the Pico 13 Oct (`chirpstack_123`), no
  frame rejected. The Mac's stock Gateway Bridges (LAN, plain into Mosquitto) are stopped and off by default.
- [x] **Constant-time MIC / tag compares** (12 Oct, 121): the Pico (`lora_aead.h`) and the application; host test
  passes; the Pico through ChirpStack on its derived key, ACL on: 60 uplinks, delay median 234.4 ms, seal / open
  unchanged. A board timing test (dudect-style) is KIV.
- [x] **The round trip Pico → application → Pico, and the Pico's cycle counts** (13 Oct, finding 124):
  `REPLY_WAIT_MS`, `chirpstack_app.py --reply` + a relay (`PUB=`), ChirpStack's `get_downlink_data_delay` (400 ms;
  `DOWNLINK_DELAY`); `seal_cyc` / `open_cyc`. Run 13 Oct: 60 / 60 replies, the Pico's round trip 650 ms.
- Evidence stays on the Pi and in local copies (`results/`, `*.log` are gitignored): rsync or the Docker logs.
- Not needed to finish (KIV): a real LoRa radio and gateway in place of the UDP air and `virtual_gateway.py`; the OTAA
  join; downlinks to the Pico; the 10 ms de-duplication run on two machines (one-Mac figure in finding 116).

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
13. [x] (Replaced on 20 Oct by Mosquitto bridges, TLS on every hop: finding 125; `scripts/stunnel` removed. Steps 13-14
    as first built:) stunnel, a TLS proxy (`scripts/stunnel`: Alpine 3.23, OpenSSL 3.5.8), in front of the Gateway Bridge
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
