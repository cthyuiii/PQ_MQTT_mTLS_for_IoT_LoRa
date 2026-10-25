# AES-256 LoRaWAN: the plan, the rules and the test vectors

docs/pending.md, item 3 (decision in finding 127). **Every LoRaWAN key is 32 bytes, and every operation is AES-256
or AES-256-CMAC**, for LoRaWAN 1.0.3, 1.0.4 and 1.1, with ABP and with OTAA. Otherwise the frames, the counters and
the 4-byte MIC are LoRaWAN's own. It isn't standard LoRaWAN: our devices work only with our ChirpStack, and the
other way round.

Done: the rules and the test vectors (below), and ChirpStack (25 Oct, below). Not started: the host tool, the Pico.

## What the test vectors are for

`scripts/aes256_vectors.sh` prints the exact bytes of ten frames and keys (V1-V10) that every AES-256 implementation
must produce: the ChirpStack fork, our host tool, and the Pico. It uses only the `openssl` command line, so the bytes
come from none of those three. When each one reproduces V1-V10 in its own tests, they agree with each other before
anything runs end to end. If an end-to-end run fails later, the vectors say which side is wrong.

## The plan: what we reuse, configure and change

| Part | Reused | Set by configuration | Changed |
|---|---|---|---|
| ChirpStack (network server and its built-in join server) | our fork `cthyuiii/chirpstack` (PQ TLS), built by `scripts/chirpstack/Dockerfile` | per device profile: MAC version (1.0.3, 1.0.4 or 1.1.0) and OTAA or ABP; region `as923` | the crypto in `lrwn`; key handling, API and UI |
| Gateway (packet forwarder, Gateway Bridge) | as now | nothing | nothing: the frames keep their size and layout, and the gateway never decrypts |
| Test device, no radio | `mqtt_tls_timer` with `AIR=1` → `virtual_gateway.py` (which already forwards join-requests) | nothing | 32-byte keys, 1.0.x frames, OTAA |
| The Pico W on the radio | Semtech's LoRaMac-node v4.7.0: 1.0.4 and 1.1, ABP and OTAA, an SX1262 driver, AS923. Arm's `lorawan-library-for-pico` runs LoRaMac-node on the RP2040. | version, keys and EUIs (`se-identity.h`) | its software secure element; Arm's port moved to v4.7.0; a board file for the SX1262 HAT |
| Our application and its end-to-end layer | as now | nothing | nothing |

### ChirpStack: done (25 Oct), in the fork's `iot-pqc` checkout (`network/chirpstack`)

In `lrwn`, ChirpStack's LoRaWAN library:

- **The key type** holds 32 bytes: `AES128Key` is now `AES256Key` (`lrwn/src/aes256.rs`), everywhere. A 16-byte key is
  refused, as hex, as bytes and from the database.
- **`phy_payload.rs`:** the frame, MIC and join functions use AES-256 and AES-256-CMAC. MICs are compared in constant
  time (`subtle`, already in `Cargo.lock`; it used `==`).
- **`keys.rs`:** `kdf()` is the KDF below. Every key derivation keeps its 16-byte block and runs it through `kdf()`:
  the session keys, JSIntKey / JSEncKey, the relay's RootWorSKey, the multicast keys and FUOTA's DataBlockIntKey.
- **Two app-layer messages grow,** because they carry a key: McGroupSetupReq (multicast setup) 29 → 45 bytes, with the
  McKey as two encrypted blocks; the relay's UpdateUplinkListReq 26 → 42 bytes. Neither is tested on a device.
- **Tests:** V1-V10 as frame and key tests; the doc examples, multicast keys and McKey encryption checked against
  openssl.

In ChirpStack itself:

- **Storage:** keys are bytes in Postgres and in the device session, so the schema doesn't change.
- **KEKs** (`[[keks]]`, the key envelopes for roaming and an external join server) are 32 bytes, AES-256 key wrap.
- **The API** takes keys as 64 hex characters and refuses anything else. **The UI** (`AesKeyInput.tsx`) takes and
  generates 64.
- **Class B ping slots** use AES-256 with the all-zero key, so a class B device must too (not tested).
- **ChirpStack's tests** use 32-byte keys. Their expected MICs and ciphertexts are the new ones, each checked so that
  only those bytes changed. The test harness now installs the TLS provider `main()` does (the PQ TLS fork had broken
  every test that touches TLS).

How it was tested: `cargo test -p lrwn --all-features` (181 and 8 doc examples), `-p backend` (6, with RFC 3394's
AES-256 key-wrap example), `-p chirpstack --features postgres` (215, against Postgres and Redis in Docker; the MQTT,
Kafka and AMQP integration tests are behind a feature and weren't run). The image: `iot-pqc/chirpstack:4.19.2-pq-aes256`.

### Test device: our host tool (`network/app_aead.c`, `mqtt_tls_timer`)

- **Keys:** `lorawan11_256` builds its 32-byte network keys today by joining two 16-byte keys. It moves to four
  independent 32-byte keys. `aes256ctr` (the 1.0.x frame) moves to two.
- **OTAA:** it sends a join-request, then reads and checks the join-accept. Then it derives the session keys (each one
  is two CMACs, which the tool already has) and sends frames with them.
- **1.0.3 and 1.0.4:** the DevNonce is random (1.0.3) or a counter kept in a file (1.0.4).
- **Self-test:** it reproduces V1-V10, as it already checks NIST's answers.
- **The Pico's Wi-Fi path** (`lora_aead.h`) gets the same key change.

### The Pico W on the radio: a fork of LoRaMac-node v4.7.0

- **Key size:** `SE_KEY_SIZE` in `src/mac/secure-element-nvm.h` and `AES_CMAC_KEY_LENGTH` in
  `src/peripherals/soft-se/cmac.h` go from 16 to 32. `soft-se.c` calls `aes_set_key` with 32: its AES code already
  takes 32-byte keys.
- **`SecureElementDeriveAndStoreKey`** in `soft-se.c` runs the KDF instead of one AES block. It already receives the
  16-byte derivation block, so `LoRaMacCrypto.c` doesn't change.
- **`se-identity.h`:** the 32-byte keys.
- **The Pico port:** Arm's `lorawan-library-for-pico` pins LoRaMac-node v4.5.1 (1.0.4 only), so its submodule moves to
  v4.7.0, along with whatever its RP2040 glue needs for that. It drives an SX1276; the Waveshare HAT is an SX1262, so
  it also needs an `sx1262-board.c` for the RP2040 (SPI, BUSY, DIO1 and reset pins), following LoRaMac-node's own
  SX1262 board files (`sx1262mbxcas-board.c`).
- **Versions:** v4.7.0 runs 1.1 and falls back to 1.0.4 (`LORAMAC_VERSION`, `LORAMAC_FALLBACK_VERSION`). With OTAA,
  the join-accept's OptNeg bit picks between them. It has no 1.0.3 mode, so 1.0.3 is tested with the host tool.
- **Test:** the secure element reproduces V1-V10.

### The order

1. `lrwn`, against V1-V10. Done.
2. ChirpStack: keys, API, UI, its tests; then the image. Done.
3. The host tool, against V1-V10.
4. End to end, six cases: 1.0.3, 1.0.4 and 1.1, each with ABP and OTAA. The path: host tool → virtual gateway →
   Gateway Bridge → ChirpStack → broker → application, and the downlink back.
5. The Pico on the radio, once the Pi 5 gateway runs (`docs/radio_gateway.md`).

## The rules

msg = the frame without its MIC. DevAddr, FCnt (4 bytes), ConfFCnt (2 bytes), JoinNonce (3), NetID (3), DevNonce (2)
and the EUIs (8) are little-endian, as in the frame. `0^n` = n zero bytes.

### Data frames

| Operation | Key | Block(s) | Result |
|---|---|---|---|
| FRMPayload, FPort > 0 | AppSKey | A_i = `01` · 0^4 · Dir · DevAddr · FCnt · `00` · i | payload XOR AES(A_1) ‖ AES(A_2) … |
| FRMPayload, FPort 0 (MAC commands) | NwkSEncKey (1.1), NwkSKey (1.0.x) | the same A_i | the same |
| FOpts, 1.1 only (plain in 1.0.x) | NwkSEncKey | A = `01` · 0^3 · x · Dir · DevAddr · FCnt · `00` · `01`; x = `02` on a downlink with FPort > 0 (AFCntDown), else `01` | FOpts XOR AES(A) |
| MIC, 1.0.x, both directions | NwkSKey | B0 = `49` · 0^4 · Dir · DevAddr · FCnt · `00` · len(msg) | CMAC(B0 ‖ msg)[0..4] |
| Uplink MIC, 1.1 | SNwkSIntKey over B1, FNwkSIntKey over B0 | B0 = `49` · 0^4 · `00` · DevAddr · FCntUp · `00` · len(msg); B1 = `49` · ConfFCnt · TxDr · TxCh · `00` · DevAddr · FCntUp · `00` · len(msg) | CMAC_S(B1 ‖ msg)[0..2] ‖ CMAC_F(B0 ‖ msg)[0..2] |
| Downlink MIC, 1.1 | SNwkSIntKey | B0 = `49` · ConfFCnt · 0^2 · `01` · DevAddr · FCntDown · `00` · len(msg) | CMAC(B0 ‖ msg)[0..4] |

Dir is `00` up and `01` down. ConfFCnt is the counter of the frame being acknowledged, used only when the ACK bit is
set (otherwise 0).

### Joins (OTAA)

| Operation | Key | Over | Result |
|---|---|---|---|
| Join-request MIC | AppKey (1.0.x), NwkKey (1.1) | MHDR · JoinEUI · DevEUI · DevNonce | CMAC[0..4] |
| Join-accept MIC, 1.0.x | AppKey | MHDR · JoinNonce · NetID · DevAddr · DLSettings · RxDelay [· CFList] | CMAC[0..4] |
| Join-accept MIC, 1.1 | JSIntKey | `FF` · JoinEUI · DevNonce · the same as 1.0.x | CMAC[0..4] |
| Join-accept encryption | AppKey (1.0.x), NwkKey (1.1) | everything after MHDR, MIC included (16 or 32 bytes) | AES *decryption* of each block, so the device only needs AES encryption to read it |

### Key derivation

LoRaWAN builds a 16-byte block for each key and encrypts it once with the root key. That gives 16 bytes. Here the same
block goes into NIST SP 800-108's KDF in counter mode, with AES-256-CMAC, for 32 bytes:

```text
key = CMAC(root, 00000001 ‖ block ‖ 00 ‖ 00000100) ‖ CMAC(root, 00000002 ‖ block ‖ 00 ‖ 00000100)
```

(The counter, the block as the KDF's label, a separator, no context, the length in bits.) This is OpenSSL's
`openssl kdf … KBKDF`, which gives the vectors an independent check. A device computes it with two CMACs, which it
already has for the MIC.

| Key | Root | Block |
|---|---|---|
| NwkSKey (1.0.x) | AppKey | `01` · JoinNonce · NetID · DevNonce · 0^7 |
| AppSKey (1.0.x) | AppKey | `02` · JoinNonce · NetID · DevNonce · 0^7 |
| FNwkSIntKey, SNwkSIntKey, NwkSEncKey (1.1) | NwkKey | `01`, `03`, `04` · JoinNonce · JoinEUI · DevNonce · 0^2 |
| AppSKey (1.1) | AppKey | `02` · JoinNonce · JoinEUI · DevNonce · 0^2 |
| JSIntKey (1.1) | NwkKey | `06` · DevEUI · 0^7 |

In 1.0.x, ChirpStack uses NwkSKey as all three network keys. The JoinNonce is ChirpStack's counter per device.

### 1.0.3, 1.0.4 and 1.1

- **1.0.3 and 1.0.4** produce the same bytes. They differ in the DevNonce: random in 1.0.3; in 1.0.4 a counter from 0,
  kept across resets. ChirpStack refuses a DevNonce it has seen before, for both.
- **1.1** has four session keys and two root keys. The device says it speaks 1.1 by its join (ChirpStack's device
  profile sets the join-accept's OptNeg bit).

### What doesn't change

AES's block is 16 bytes at any key length. The keystream comes in the same 16-byte blocks, and the CMAC is still 16
bytes, cut to the same 4 (or 2 + 2). So the frames keep their size and layout: **the gateway and the radio don't
change**, and neither does the airtime.

The MIC is still 4 bytes, so a forged frame still passes with a chance of 2^-32 per try. AES-256 adds margin against
recovering the keys (Grover's algorithm halves a key's effective length against a quantum attacker). It doesn't
lengthen the MIC.

## Not included

- **Rejoin-requests (1.1):** ChirpStack doesn't handle them (its uplink code takes only join-requests and data), so
  JSEncKey is never used.
- **Class B and C, multicast, FUOTA, relay, roaming:** not tested.
- **Our end-to-end layer** (`lorawan11_e2e`) stays inside FRMPayload, unchanged.

## Test vectors

`bash scripts/aes256_vectors.sh` (OpenSSL 3.x; `OSSL=` points at another `openssl`). First, five controls must pass:
AES-256 encryption and decryption (FIPS 197 C.3), AES-256-CMAC (SP 800-38B examples 9 and 12), and openssl's KDF
against two plain CMACs. The output is the same on OpenSSL 3.5 (Debian 13), 3.6 and 4.0 (macOS).

The block layouts are LoRaWAN's. On 25 Oct, the script's functions were checked once against 13 frames and keys that
ChirpStack's `lrwn` and its Go library publish; the fork's tests check them again. Those checks aren't kept here,
because they use standard keys.

Each key below has its own pattern, so a swapped key shows. DevAddr is `01234567` (in the frame: `67452301`).

### 1.1, ABP (V1-V4)

| Key | Value |
|---|---|
| AppSKey | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| FNwkSIntKey | `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f` |
| SNwkSIntKey | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |
| NwkSEncKey | `606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f` |

**V1, uplink:** unconfirmed, FCnt 1, FPort 1, TxDr 2, TxCh 1. The payload is the 31-byte reading
`{"seq":1,"temp_c":21.5,"rh":48}`.

```text
FRMPayload  eeccb898c8050f10c7774eefebb3632aa0bc573cc34bf30be2ae0f576c0127
MIC         1238d44f
frame       406745230100010001eeccb898c8050f10c7774eefebb3632aa0bc573cc34bf30be2ae0f576c01271238d44f
```

**V2, uplink with an ACK and MAC commands:** acknowledges downlink 7 (ConfFCnt 7), FCnt 2, TxDr 5, TxCh 2. FOpts
carries DevStatusAns `067307`, encrypted with NwkSEncKey. FPort 1, payload `hi`.

```text
FOpts       56e8b2
FRMPayload  38a7
MIC         0827dd05
frame       406745230123020056e8b20138a70827dd05
```

**V3, downlink with MAC commands:** AFCntDown 5. FOpts carries LinkCheckAns `020701`, encrypted with NwkSEncKey using
the AFCntDown block. FPort 1, payload `01020304`.

```text
FOpts       32fd3c
FRMPayload  df219942
MIC         a8cef152
frame       606745230103050032fd3c01df219942a8cef152
```

**V4, downlink on FPort 0:** acknowledges uplink 3 (ConfFCnt 3), NFCntDown 9. FRMPayload carries LinkADRReq
`0351ff0001`, encrypted with NwkSEncKey.

```text
FRMPayload  b76ae989f2
MIC         ef6c021d
frame       606745230120090000b76ae989f2ef6c021d
```

### 1.0.3 and 1.0.4, ABP (V5-V6)

AppSKey as above; NwkSKey `808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f`.

**V5, uplink:** unconfirmed, FCnt 1, FOpts DevStatusAns `067307` (plain in 1.0.x), FPort 1, the reading.

```text
FRMPayload  eeccb898c8050f10c7774eefebb3632aa0bc573cc34bf30be2ae0f576c0127
MIC         13808b44
frame       406745230103010006730701eeccb898c8050f10c7774eefebb3632aa0bc573cc34bf30be2ae0f576c012713808b44
```

**V6, downlink on FPort 0:** ACK, FCntDown 4. FRMPayload carries LinkADRReq `0351ff0001`, encrypted with NwkSKey.

```text
FRMPayload  442794bf53
MIC         f1e5ff9c
frame       606745230120040000442794bf53f1e5ff9c
```

### OTAA (V7-V10)

JoinEUI `1122334455667788`, DevEUI `0102030405060708`, DevNonce 1, JoinNonce 1, NetID `000013`, DevAddr `01234567`;
DLSettings RX2 DR2, RxDelay 1, no CFList.

| Root key | Value |
|---|---|
| AppKey (1.0.x) | `a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf` |
| NwkKey (1.1) | `c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf` |
| AppKey (1.1) | `e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff` |

**V7, 1.0.x join-request:**

```text
frame       00887766554433221108070605040302010100bc001704
```

**V8, 1.0.x join-accept** (DLSettings `02`), and the keys both sides derive:

```text
plain       20 010000130000674523010201 3b6b4ada
frame       202dfba0e58af087a565171f76ae4720ce
NwkSKey     24e1abfe96dadf7c39554fbeef6fbcaf1eb40db3a0bad61f5262da0841d493d4
AppSKey     1d25efdb4e5bda08d8d3e6b9134e3a6b8b8fc5b5001f72b2a13f7bc2ba75ce6d
```

**V9, 1.1 join-request:**

```text
frame       0088776655443322110807060504030201010084b19606
```

**V10, 1.1 join-accept** (DLSettings `82`: OptNeg), and the keys:

```text
JSIntKey    66bea5492e78763d16f359a45cf3fb1db37bc02458bee1370fe90fd978f92f24
plain       20 010000130000674523018201 27ded561
frame       204e91a3c904b43c2f393db3159f8abbfc
FNwkSIntKey ee721af87f630a64f6943a8bbb3fafe2442dace93331ba441c8601fc05f07523
AppSKey     b0fcc761250f51aea1620b827eeef9ef18b84b1099658423c01fa486040cbdcc
SNwkSIntKey 5aa0dfcfacbf19288136a689ab18c1bb6685dae2529a016823b210fbb178cde5
NwkSEncKey  a496763652fdca82b5d7caf81189fb69e131b8345fa538448890e2b322e38897
```
