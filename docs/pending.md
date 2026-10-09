# Pending: LoRa_1.1_implementation

What this branch still needs: a simulated ChirpStack network (no radio) that accepts our LoRaWAN 1.1 frames,
with 256-bit protection end to end. Nothing below is built or tested yet unless marked.
Labels: **G&B** = Gateway & Backend, **B&R** = Benchmarking & Reproducibility.

## Decided (9 Oct 2026)

- 256-bit: ChirpStack stays stock. The LoRaWAN layer stays standard (AES-128), and an AES-256 layer inside the
  payload passes through ChirpStack untouched; only the application decrypts it (section 4, option B).
- Test ChirpStack's own TLS: the hybrid key exchange, then ML-DSA certificates (section 5).
- Define a 256-bit key derivation (section 6).
- Report the delay ChirpStack adds (section 7).

## 1. Run ChirpStack (v4, Docker) — G&B

```bash
git clone https://github.com/chirpstack/chirpstack-docker.git
cd chirpstack-docker
docker compose up -d        # web UI on http://<host>:8080, login admin / admin
```

| Service | Role |
|---|---|
| ChirpStack | Network server, application server and join server in one |
| Gateway Bridge | Semtech UDP on port 1700 → MQTT |
| Mosquitto | ChirpStack's own broker on 1883 (separate from our PQ broker) |
| Postgres, Redis | ChirpStack's storage |

- [ ] Region: the compose file defaults to EU868. For Singapore (AS923), change the Gateway Bridge topic prefix and
  ChirpStack's enabled region (both in `docker-compose.yml` / the config files it mounts).
- [ ] Port 1883: remap the compose broker if a Mosquitto already listens there. Our PQ brokers use 18830 and up.
- [ ] Two machines (our rule for every TLS result): gateway side (virtual gateway + Gateway Bridge) on one
  machine, ChirpStack and its broker on the other, so the bridge → broker TLS link crosses the network.
  In a real network the Gateway Bridge runs on the gateway, and the plain UDP hop stays inside that box.
- [ ] In the UI create:
  - a device profile: MAC version 1.1.0, OTAA off (ABP), ADR off (stops MAC-command downlinks), Class A;
  - a gateway (any 8-byte ID);
  - an application with one device.
- [ ] Activate the device (ABP): DevAddr, the four 1.1 session keys, uplink FCnt = the device's current FCnt.

## 2. Virtual gateway (replaces radio + gateway) — G&B

A short stdlib Python script on the gateway-side machine:

1. Subscribes to our PQ broker (`pqc/pipe/#`). Each message is already a LoRaWAN PHYPayload:
   MHDR | DevAddr | FCtrl | FCnt | FPort | 51-byte payload | MIC (64 B).
2. Wraps each frame in a Semtech UDP `PUSH_DATA` and sends it to the Gateway Bridge on port 1700.

```python
rxpk = {"tmst": t_us & 0xFFFFFFFF, "chan": 0, "rfch": 0, "freq": 868.1, "stat": 1, "modu": "LORA",
        "datr": "SF12BW125", "codr": "4/5", "rssi": -60, "lsnr": 9.5,
        "size": len(phy), "data": base64.b64encode(phy).decode()}
sock.sendto(b"\x02" + os.urandom(2) + b"\x00" + gateway_eui + json.dumps({"rxpk": [rxpk]}).encode(), (bridge_host, 1700))
```

- [ ] `PULL_DATA` keep-alive every few seconds (gateway shows online; downlinks come back as `PULL_RESP`; log them first).
- [ ] One runnable self-check (packet layout).

Path: Pico W → PQ mTLS → our Mosquitto → virtual gateway → UDP → Gateway Bridge → ChirpStack →
ChirpStack's uplink event (MQTT JSON) → our application.

## 3. What in our code ChirpStack will trip on — G&B

- [ ] **Uplink MIC fields.** Our 1.1 uplink MIC uses TxDr = 0, TxCh = 0 (`network/app_aead.c`, `mic()`).
  ChirpStack recomputes them from what the gateway reports, so the virtual gateway must report channel 0 at DR0
  (SF12BW125: 868.1 MHz EU868, 923.2 MHz AS923-1). Or make TxDr / TxCh settable.
  The 51-byte payload is exactly DR0's maximum (EU868 / AS923 without dwell time).
- [ ] **Fixed device.** Hosts make a per-process DevAddr (0x26 + pid) and random keys unless `APP_KEYS` is set.
  Add a `DEV_ADDR` option; use a fixed `APP_KEYS`.
- [ ] **DevAddr range.** Pick one inside ChirpStack's NetID (NetID 000000 → 00000000–01FFFFFF), e.g. 01 23 45 67.
  On air it is little-endian, in ChirpStack's UI big-endian.
- [ ] **Key mapping** (ChirpStack's ABP form):

  | ChirpStack key | Ours |
  |---|---|
  | FNwkSIntKey | `APP_KEYS` bytes 32–47 (`k_nwk`) |
  | SNwkSIntKey | `APP_KEYS` bytes 48–63 (`k_nwk2`) |
  | NwkSEncKey | anything (no MAC commands sent) |
  | AppSKey | with option B: a new 16-byte LoRaWAN AppSKey; the 32-byte `k_app` becomes the inner AES-256 key that ChirpStack never sees |

- [ ] **Frame counter.** Only the low 16 bits travel; ChirpStack rebuilds the rest from its session. Start the
  activation's uplink FCnt at the device's counter. "Skip frame-counter check" for debugging only.

## 4. The 256-bit question — decided: option B

LoRaWAN 1.1 defines AES-128 only, and ChirpStack's keys are 16 bytes throughout (key type, database, API, UI).
Stock ChirpStack drops `lorawan11_256` frames (MIC check fails).

| Option | How | Gives | Costs |
|---|---|---|---|
| A. Patch ChirpStack | Fork the Rust code: 256-bit MIC + payload, 32-byte keys everywhere, new join derivation | 256-bit LoRaWAN-style server | Large; a fork; not standard |
| **B. Pass-through (chosen)** | Standard LoRaWAN 1.1 (AES-128) for ChirpStack + AES-256 on the reading inside the payload, decrypted only by our application | Stock ChirpStack; 256-bit end-to-end confidentiality; ChirpStack's operator can't read the reading | MIC stays AES-128; one extra AES pass per frame; 0 extra bytes |
| C. Own receiver for 256 | ChirpStack for 128-bit only; `lorawan11_256` checked by our receiver | Today's `lorawan11_256` measured end to end | 256-bit frames never pass ChirpStack |

Option B in detail:
- The MIC cannot pass through: ChirpStack checks it first and drops frames that fail, so it stays standard AES-128-CMAC.
  It is 4 bytes, so forgery is 1 in 2^32 per try whatever the key size; 256-bit MIC keys would not change that.
- Device: reading → AES-256-CTR under `k_app` (reuse the existing `aes256ctr` keystream code) → FRMPayload →
  standard `lorawan11` seal (AppSKey-128 + MIC). New scheme name, e.g. `lorawan11_e2e`.
- Counter block: DevAddr + 32-bit FCnt + direction (LoRaWAN's A-block layout, different key). ChirpStack's uplink
  event carries `devAddr` and `fCnt`, so the application rebuilds it: no extra bytes.
- ChirpStack removes the outer AES-128 layer and publishes the inner ciphertext as the event's `data` (base64).
- [ ] Decide inner integrity: none (trust ChirpStack's MIC + PQ TLS from ChirpStack), or a truncated
  AES-256-CMAC tag inside the payload (4 B → 47-byte reading).
- [ ] Keep `lorawan11_256` as the comparison row.
- [ ] Pico side (`lora_aead.h`) + host test frames byte-for-byte, as for the other schemes.

## 5. ChirpStack's TLS: hybrid key exchange and ML-DSA certificates — G&B

Their TLS stacks are not OpenSSL + oqs-provider (checked 9 Oct in upstream `Cargo.toml` / `go.mod`):

| Link | Client stack | X25519MLKEM768 | ML-DSA certificates |
|---|---|---|---|
| Gateway Bridge → broker | Go 1.25 `crypto/tls`, paho.mqtt.golang 1.5.1 | expected yes (Go default since 1.24) | expected no (`crypto/x509`) |
| ChirpStack → broker | rustls 0.23 with the `ring` provider, rumqttc 0.25 | expected no (`ring` has no ML-KEM) | expected no |
| Our application → broker | OpenSSL 3.5 + oqs-provider / wolfSSL | tested | tested |

- [ ] Test each link against our PQ broker in this order: hybrid key exchange + classical certificate; then an
  ML-DSA-44 server certificate; then ML-DSA client certificates (mTLS). Record pass / fail and the error.
- [ ] Fallbacks if a link fails: rebuild ChirpStack with rustls' `aws-lc-rs` provider (has X25519MLKEM768);
  or a local TLS proxy on OpenSSL 3.5 (native ML-KEM and ML-DSA) next to the component; or mixed certificates
  (PQ key exchange, classical certificate) on that link.
- [ ] Keep ChirpStack's compose broker on a private Docker network until its links are PQ.

## 6. 256-bit key derivation — G&B with Security & Key Management

- [ ] Define how the 32-byte inner key is derived and from what root, e.g. HKDF-SHA-256 (RFC 5869) or
  SP 800-108 with AES-256-CMAC, from a 256-bit device root key; inputs: DevAddr (ABP) or
  JoinNonce | JoinEUI | DevNonce (OTAA, later); a label and version string.
- [ ] Replace the ad hoc nwk‖nwk2 / nwk2‖nwk layout of `lorawan11_256`, or mark it as comparison only.
- [ ] Where the root key lives: device (hardening table: key storage) and application backend, never ChirpStack.
- Proposal, not decided: refresh the key with ML-KEM over LoRa. The device holds the backend's ML-KEM public key
  (installed like our trust anchor, updated by the signed update) and sends one ciphertext uplink
  (ML-KEM-512: 768 B = 16 frames at DR0, 4 at DR5); both sides feed the shared secret into the derivation.

## 7. Delay added by ChirpStack — B&R

- [ ] Time from the virtual gateway's `PUSH_DATA` to our application receiving the uplink event, per frame
  (median / p95 as in the other tables), on the same clock.
- [ ] Report the de-duplication delay separately: ChirpStack waits for copies from other gateways
  (`deduplication_delay`, 200 ms default). Measure at the default and at a low value.
- [ ] Note the run's ChirpStack, Gateway Bridge and Docker image versions (provenance).

## Order

Machines: **Mac** = ChirpStack, Postgres, Redis and ChirpStack's Mosquitto (on 1884: the Mac's own Mosquitto has 1883).
**Pi 4** = our PQ broker (`--serve-broker`, as for the Pico), the virtual gateway and the Gateway Bridge (UDP 1700 stays
inside the Pi, as on a real gateway). **Device** = a host client on the Mac first, then the Pico W.

1. [ ] ChirpStack up on the Mac (README section 0.4), Gateway Bridge on the Pi (`scripts/setup_gateway_pi.sh`).
   Built 9 Oct, not run yet.
   Done when: the UI opens and the bridge's MQTT connection shows in ChirpStack's broker log.
2. [ ] Virtual gateway `network/virtual_gateway.py` (stdlib): stdin frames → `PUSH_DATA` (channel 0, DR0), `PULL_DATA`
   keep-alive, logs `PUSH_ACK` / `PULL_RESP`, prints the send time per FCnt; `--selftest` checks the packet layout.
   Done when: the gateway shows online in ChirpStack. Built 9 Oct: `--selftest` passes, and a loopback run against a
   stand-in bridge got the frame, stats, keep-alive and a downlink acknowledgement. Not yet run against the real bridge.
3. [ ] Smoke test with a known-good frame: the published LoRaWAN 1.0 uplink from the `app_aead.c` self-test
   (DevAddr 49BE7DF1, FCnt 2, payload "test", its keys) to a temporary LoRaWAN 1.0 ABP device.
   Done when: the event shows "test". Proves gateway → bridge → ChirpStack before our 1.1 code is involved.
4. [ ] Fixed device on the host client (`mqtt_tls_timer.c`): `DEV_ADDR` replaces the per-process DevAddr; with it set,
   the FCnt is kept in a file and reserved ahead (as the Pico does in flash), so a restart never reuses a counter under
   the same keys and ChirpStack never sees it go back. Check: two runs in a row continue the counter;
   `aead_host_test` still byte-identical.
5. [ ] Frames out of the PQ broker: `SUB=pqc/pipe/#` watch mode prints the raw frame (hex) per message with `RAW=1`,
   piped into the virtual gateway. It reuses the client's PQ TLS and our certificates: no MQTT library in Python.
6. [ ] LoRaWAN 1.1 end to end with the host client: a 1.1 ABP device with the section 3 key mapping.
   Done when: the events show the 51-byte readings (`{"seq":n,...}`) in order, with no MIC or FCnt errors.
7. [ ] The Pico W as the device: register its DevAddr and keys (kept in flash by the deployment firmware).
8. [ ] Option B, `lorawan11_e2e`: `app_aead.c`, `lora_aead.h`, `aead_host_test`, plus the application side that
   decrypts the event's `data` (OpenSSL, no new Python dependency).
9. [ ] PQ TLS on Gateway Bridge → broker and ChirpStack → broker (section 5).
10. [ ] ChirpStack delay (section 7): the virtual gateway's send time to the application's receive time, on the Pi's clock.
11. [ ] Downlinks: `PULL_RESP` → `TX_ACK`, delivered to the device through the PQ broker.
12. [ ] OTAA join (KIV), with the derivation from section 6.
