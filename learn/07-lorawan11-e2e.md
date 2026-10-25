# Lab 7 — LoRaWAN 1.1 and our 256-bit layer

## What 1.1 changes

LoRaWAN 1.1 keeps the frame layout from lab 6, but splits the network key into three:

| 1.0.x | 1.1 | Used for |
|---|---|---|
| AppSKey | AppSKey | encrypting the payload (unchanged) |
| NwkSKey | FNwkSIntKey | half of an uplink's MIC, which a *forwarding* network (roaming) can check |
| | SNwkSIntKey | the other half, and the whole downlink MIC: the device's own (*serving*) network |
| | NwkSEncKey | encrypting MAC commands (the network's own messages, in FOpts or on FPort 0) |

The uplink MIC becomes two CMACs: 2 bytes under SNwkSIntKey (over block B1) and 2 under FNwkSIntKey (over B0). B1
adds the radio data rate and channel; when those are 0, as in this lab, B1 has the same bytes as B0.

## Step 1: a 1.1 downlink, from ChirpStack's own test suite

This downlink is a test vector in ChirpStack's LoRaWAN library (`phypayload_test.go`). It carries 3 bytes of
encrypted MAC commands in FOpts and no payload. SNwkSIntKey is sixteen `02` bytes.

```bash
cd /lab
block() { echo "$1"00000000"$2$DEVADDR$FCNT"00"$3"; }   # from lab 6
SNWK=02020202020202020202020202020202
FRAME=60040302010300000207010177701EA3
echo $FRAME | sed -E 's/^(..)(.{8})(..)(.{4})(.{6})(..)(.{8})$/MHDR=\1 DevAddr=\2 FCtrl=\3 FCnt=\4 FOpts=\5 FPort=\6 MIC=\7/'
DEVADDR=04030201; FCNT=00000000
```

**Predict:** which key makes this MIC, and what goes in B0's Dir byte and length?

<details><summary>Answer</summary>

SNwkSIntKey, Dir `01` (a downlink), length 12 (`0C`: the whole frame without its MIC). FCtrl `03` says FOpts is 3
bytes long. Check it:

```bash
echo $(block 49 01 0C)${FRAME:0:24} | xxd -r -p | openssl mac -cipher AES-128-CBC -macopt hexkey:$SNWK CMAC
```

`77701EA3...` = the frame's MIC.

</details>

## Our 256-bit layer (`lorawan11_e2e`)

ChirpStack holds AppSKey, so it can read every reading. The project adds a layer inside the payload, under a 32-byte
key that **only the application** has:

```text
reading ──AES-256-CTR (e2e key)──► inner ciphertext ‖ 4-byte tag (AES-256-CMAC)
        ──normal LoRaWAN 1.1 (AppSKey, the two MIC keys)──► frame on FPort 2
```

ChirpStack checks the MIC and removes the outer layer as usual. What it hands the application is still encrypted.
The tag uses its own key, derived from the e2e key: `AES-256(e2e key, 02 00…00) ‖ AES-256(e2e key, 03 00…00)`.

## Step 2: our device code makes a frame, and you open it

Copy the project's C code into the container. On your machine, from the repository root, with the container running
(`docker start pqc-lab`):

```bash
tar -c network/*.c network/*.h pico/sketches/mqtt_tls_bench/hs_timing.h | docker exec -i pqc-lab tar -x -C /lab
```

In the container, build the project's MQTT client (`mqtt_tls_timer`; lab 8 times things with it). If lab 3's broker
isn't running (after a restart), start it again:

```bash
cd /lab/network
cc -O2 -DHS_TIMING -I../pico/sketches/mqtt_tls_bench mqtt_tls_timer.c app_aead.c hs_timing_openssl.c -ldl -lssl -lcrypto -lm -o mqtt_tls_timer
cd /lab
pgrep mosquitto > /dev/null || { mosquitto -c broker.conf > broker.log 2>&1 & sleep 1; }
```

Fixed keys, so you can open the frame by hand. In `APP_KEYS` order: a 32-byte app key (AppSKey is its first 16 bytes),
FNwkSIntKey, SNwkSIntKey, the 32-byte e2e key:

```bash
K=$(printf '11%.0s' {1..32})$(printf '22%.0s' {1..16})$(printf '33%.0s' {1..16})$(printf '55%.0s' {1..32})
C="certs/CA.crt certs/client.crt certs/client.key"
RAW=1 SUB='pqc/#' network/mqtt_tls_timer localhost 8883 1 0 $C > frames.txt 2> watch.err &   # a subscriber printing raw frames
sleep 1
APP_KEYS=$K AEAD=lorawan11_e2e MSGS=1 PAYLOAD=31 network/mqtt_tls_timer localhost 8883 1 0 $C | grep '^#aead'
sleep 1; cat frames.txt
F=$(awk '{print $3}' frames.txt | head -1 | tr a-f A-F)
echo $F | sed -E 's/^(..)(.{8})(..)(.{4})(..)(.*)(.{8})$/MHDR=\1 DevAddr=\2 FCtrl=\3 FCnt=\4 FPort=\5 FRMPayload=\6 MIC=\7/'
```

The device sent one reading over PQ mTLS through the broker, and your subscriber printed it as it passed.

**You are ChirpStack:** check the MIC (two halves), then remove the outer layer.

```bash
APPSKEY=11111111111111111111111111111111; FNWK=22222222222222222222222222222222; SNWK=33333333333333333333333333333333
DEVADDR=${F:2:8}; FCNT=${F:12:4}0000                 # from the header; FCnt is small, so its top 2 bytes are 00
N=$(( ${#F} / 2 - 4 )); LEN=$(printf %02X $N); MSG=${F:0:$((2*N))}   # the frame without its MIC
cmac() { xxd -r -p | openssl mac -cipher AES-$2-CBC -macopt hexkey:$1 CMAC; }   # cmac <key> <128|256>
S=$(echo $(block 49 00 $LEN)$MSG | cmac $SNWK 128)   # B1 = B0 here
FM=$(echo $(block 49 00 $LEN)$MSG | cmac $FNWK 128)
echo "computed ${S:0:4}${FM:0:4}, frame ${F: -8}"
INNER=$(echo ${MSG:18} | xxd -r -p | openssl enc -aes-128-ctr -K $APPSKEY -iv $(block 01 00 01) | xxd -p | tr -d '\n' | tr a-f A-F)
echo $INNER
```

**Predict:** `INNER` is what ChirpStack passes to the application. Can ChirpStack read the reading in it?

<details><summary>Answer</summary>

The two halves match the frame's MIC. And no: `INNER` is still ciphertext (31 bytes), followed by the 4-byte tag.
Without the e2e key, ChirpStack has nothing to decrypt it with.

</details>

**You are the application:** check the tag, then decrypt.

```bash
E2E=5555555555555555555555555555555555555555555555555555555555555555
KMAC=$(echo 02000000000000000000000000000000 03000000000000000000000000000000 | xxd -r -p | openssl enc -aes-256-ecb -K $E2E -nopad | xxd -p | tr -d '\n')
CT=${INNER:0:$((${#INNER}-8))}; L2=$(printf %02X $(( ${#CT} / 2 )))
T=$(echo $(block 49 00 $L2)$CT | cmac $KMAC 256); echo "computed ${T:0:8}, frame ${INNER: -8}"
echo $CT | xxd -r -p | openssl enc -aes-256-ctr -K $E2E -iv $(block 01 00 01); echo
```

<details><summary>Answer</summary>

The tag matches, and the reading appears: `{"seq":1,"temp_c":21.5,"rh":48}`.

Why the inner tag matters: ChirpStack holds all the LoRaWAN keys, so it could change the inner ciphertext and compute
a fresh, valid MIC. The application would still catch it, because the tag needs a key ChirpStack doesn't have.
`app_aead_selftest()` in `network/app_aead.c` tests exactly that case.

</details>

## Step 3: what each layer costs in bytes

```bash
for a in lorawan10 lorawan11 lorawan11_256 lorawan11_e2e aes256gcm; do
  AEAD=$a MSGS=1 PAYLOAD=31 network/mqtt_tls_timer localhost 8883 1 0 $C | grep '^#aead' | cut -d' ' -f2- ; done
```

**Predict:** the radio is slow (lab 6's 4-byte MIC exists to save airtime). How many bytes do the 256-bit inner layer
and AES-256 keys add to a frame?

<details><summary>Answer</summary>

For a 31-byte reading:

| Scheme | Added bytes |
|---|---|
| LoRaWAN 1.0.x / 1.1 | 13 (9 header + 4 MIC) |
| `lorawan11_256` (the 1.1 frame with 256-bit keys) | 13 |
| `lorawan11_e2e` (our inner layer) | 17 |
| AES-256-GCM, for comparison | 25 (9 + a 16-byte tag) |

- **256-bit keys add nothing:** AES's block is 16 bytes whatever the key length, the CTR keystream adds no padding,
  and the MIC stays 4 bytes. That's why the planned AES-256 LoRaWAN needs no change at the gateway or on the air. Only
  the device and ChirpStack have to change.
- **The inner layer adds 4:** its tag. That's 4 bytes of airtime per uplink.
- Today `lorawan11_256` builds its 256-bit MIC keys by joining two 16-byte keys: a stand-in for benchmarks. The plan is
  four independent 32-byte keys.

</details>

Next: [lab 8, benchmarks](08-benchmarks.md).
