# Lab 8 — Benchmarks: what each part costs

Three levels: each algorithm on its own, whole TLS and mTLS handshakes, and the frame protection from labs 6-7. Then
the same measurements from the project's Pi 4 and Pico W.

The answers show one run in this container on an Apple-silicon Mac (Docker Desktop). Your numbers will differ: compare
the **ratios**, not the values.

## Step 1: each algorithm on its own

```bash
cd /lab
openssl speed -seconds 1 ML-KEM-512 ML-KEM-768 ML-KEM-1024 ecdhx25519 ecdhp256 2>/dev/null | grep -v -E '^(compiler|CPUINFO)'
openssl speed -seconds 1 ML-DSA-44 ML-DSA-65 ML-DSA-87 ecdsap256 ed25519 rsa2048 2>/dev/null | grep -v -E '^(compiler|CPUINFO)'
```

**Predict:** is ML-KEM-768 slower than X25519? Is ML-DSA-44 slower than ECDSA P-256 at signing? At verifying?

<details><summary>Answer</summary>

Operations per second in our run, and the sizes that go on the wire:

| Algorithm | Speed (per second) | Public key / output on the wire |
|---|---|---|
| X25519 | 26,108 key agreements | 32 B / 32 B |
| ML-KEM-768 | 26,154 keygens, 38,980 encaps, 26,216 decaps | 1,184 B / 1,088 B (ciphertext) |
| ECDSA P-256 | 55,104 signs, 17,999 verifies | 64 B / about 72 B (signature) |
| Ed25519 | 33,175 signs, 11,380 verifies | 32 B / 64 B |
| ML-DSA-44 | 1,964 signs, 11,055 verifies | 1,312 B / 2,420 B |
| ML-DSA-87 | 1,054 signs, 4,605 verifies | 2,592 B / 4,627 B |
| RSA-2048 | 1,766 signs, 67,798 verifies | 256 B / 256 B |

- **ML-KEM is as fast as X25519.** Its cost is **size**: about 2.3 KB on the wire against 64 bytes.
- **ML-DSA signs about 28× slower than ECDSA here, and verifies about 1.6× slower.** Its signature is about 34×
  bigger.
- The ratios depend on the machine. On the Pico W (finding 85), with wolfSSL in plain C, the key-exchange crypto is
  ML-KEM-768 22.8 ms against X25519 113.9 ms. ML-KEM is **5× faster** there, because X25519's big-number maths is slow
  on a Cortex-M0+. Signing in a handshake: Ed25519 28 ms, ECDSA P-256 43 ms, ML-DSA-44 0.16 s, RSA-2048 0.97 s.

</details>

## Step 2: a broker for the comparisons

If you haven't built `mqtt_tls_timer` yet, copy the code in and build it as in [lab 7, step 2](07-lorawan11-e2e.md).
Two more certificate sets, made with lab 2's steps:

```bash
mkset() {  # mkset <folder> <genpkey options>: lab 2's two CAs, a broker and a device certificate
  mkdir -p $1 && ( cd $1
    for c in CA ClientCA; do
      openssl genpkey "${@:2}" -out $c.key && openssl req -x509 -new -key $c.key -out $c.crt -days 30 -subj "/CN=$1 $c"
    done
    openssl genpkey "${@:2}" -out server.key
    openssl req -new -key server.key -subj /CN=localhost | openssl x509 -req -CA CA.crt -CAkey CA.key -CAcreateserial \
      -days 30 -out server.crt -extfile <(echo subjectAltName=DNS:localhost,IP:127.0.0.1)
    openssl genpkey "${@:2}" -out client.key
    openssl req -new -key client.key -subj /CN=lab-device | openssl x509 -req -CA ClientCA.crt -CAkey ClientCA.key \
      -CAcreateserial -days 30 -out client.crt
    chown mosquitto server.key ) 2>/dev/null
}
mkset ecdsa -algorithm EC -pkeyopt ec_paramgen_curve:P-256
mkset mldsa87 -algorithm ML-DSA-87
```

One broker with four listeners: mTLS and TLS-only with lab 2's ML-DSA-44 set, then mTLS with each new set. It's like
the project's broker (`network/mqtt_bench.py`), which also runs one listener per certificate type:

```bash
listener() {  # listener <port> <certificate folder> <1 = mTLS, 0 = TLS>
  printf 'listener %s\ntls_version tlsv1.3\ncafile /lab/%s/ClientCA.crt\ncertfile /lab/%s/server.crt\nkeyfile /lab/%s/server.key\n' $1 $2 $2 $2
  [ $3 = 1 ] && printf 'require_certificate true\nuse_identity_as_username true\nallow_anonymous false\n' \
             || printf 'require_certificate false\nallow_anonymous true\n'
}
{ echo per_listener_settings true; echo log_dest stdout
  listener 8883 certs 1; listener 8884 certs 0; listener 8885 ecdsa 1; listener 8886 mldsa87 1; } > bench.conf
printf 'openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = sys\n[sys]\nGroups = X25519MLKEM768:X25519:MLKEM768:MLKEM1024:SecP256r1MLKEM768\n' > groups.cnf
chown mosquitto certs/server.key
pkill mosquitto; sleep 1                    # let the old broker free its ports
OPENSSL_CONF=/lab/groups.cnf mosquitto -c bench.conf > bench.log 2>&1 &
sleep 1; tail -1 bench.log                  # "mosquitto version ... running"
```

`groups.cnf` lists the key exchanges the broker accepts. Without it, OpenSSL's default list refuses pure ML-KEM and
SecP256r1MLKEM768 with `alert handshake failure`: the server's list decides, as in lab 4 #7.

`mqtt_tls_timer <host> <port> <connections> <warm-up> <CA> [<cert> <key>]` connects, does the handshake and MQTT
CONNECT, and prints one CSV row per connection. Built with `-DHS_TIMING`, it also times its own crypto inside each
handshake: `hs_keygen_us` (key share), `hs_derive_us` (completing it), `hs_verify_us` (checking the broker's
certificate and signature) and `hs_sign_us` (its own signature, mTLS). A helper prints a column's median:

```bash
med() { awk -F, -v n=$1 '$1=="iter"{for(i=1;i<=NF;i++) if($i==n) c=i; next} c && $1~/^[0-9]+$/ {print $c}' | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
T=network/mqtt_tls_timer
```

## Step 3: TLS against mTLS

```bash
$T localhost 8884 50 5 certs/CA.crt > tls.csv
$T localhost 8883 50 5 certs/CA.crt certs/client.crt certs/client.key > mtls.csv
for f in tls mtls; do echo "$f: handshake $(med tls_ms < $f.csv) ms; sent $(med hs_tx_B < $f.csv) B, received $(med hs_rx_B < $f.csv) B; key share $(med hs_keygen_us < $f.csv) + $(med hs_derive_us < $f.csv) us, verify $(med hs_verify_us < $f.csv) us, sign $(med hs_sign_us < $f.csv) us"; done
```

**Predict:** mTLS adds the client's certificate and signature. How much longer is the handshake, and how many more
bytes does the device send?

<details><summary>Answer</summary>

| | Handshake | Device sends | Device receives | Key share + completion | Verify | Sign |
|---|---|---|---|---|---|---|
| TLS | 4.25 ms | 1,482 B | 7,797 B | 306 + 260 µs | 335 µs | - |
| mTLS | 5.22 ms | 7,955 B | 7,881 B | 323 + 252 µs | 336 µs | 586 µs |

- mTLS: about 1 ms more here (most of it the device's ML-DSA signature), and the device sends **5× more**: its 4 KB
  certificate plus a 2.4 KB signature (lab 3).
- The device's own crypto is about a quarter of the handshake here. The rest is the broker's work and the protocol.
- **The same handshake on the project's devices** (ML-DSA-44, X25519MLKEM768, wolfSSL):
  - Pi 4 (finding 83): TLS 18.5 ms, mTLS 20.2 ms. Its own crypto is about 10%.
  - Pico W (finding 85): TLS 284.8 ms, mTLS 501.3 ms. Key share 66.6 ms, completion 70.7 ms, verify 58.5 ms,
    sign 158.9 ms: its own crypto is most of the handshake. On a small device the client's crypto *is* the cost,
    which is why the project measures on the Pico itself.

</details>

## Step 4: the key exchange groups

```bash
for g in X25519 MLKEM768 X25519MLKEM768 SecP256r1MLKEM768 MLKEM1024; do
  GROUP=$g $T localhost 8884 50 5 certs/CA.crt > g.csv
  echo "$g: handshake $(med tls_ms < g.csv) ms; key share $(med hs_keygen_us < g.csv) + $(med hs_derive_us < g.csv) us; sent $(med hs_tx_B < g.csv) B, received $(med hs_rx_B < g.csv) B"
done
```

**Predict:** which group makes the device send the most? Which one is slowest?

<details><summary>Answer</summary>

| Group | Handshake | Key share + completion | Device sends | Device receives |
|---|---|---|---|---|
| X25519 (classical) | 3.69 ms | 98 + 106 µs | 306 B | 6,725 B |
| MLKEM768 | 3.44 ms | 179 + 130 µs | 1,450 B | 7,781 B |
| X25519MLKEM768 (ours) | 4.00 ms | 274 + 250 µs | 1,482 B | 7,797 B |
| SecP256r1MLKEM768 | 4.30 ms | 269 + 280 µs | 1,515 B | 7,846 B |
| MLKEM1024 | 4.20 ms | 232 + 178 µs | 1,834 B | 8,261 B |

- Post-quantum costs **bytes** much more than time: the device sends about 5× more than with X25519 alone (1.5-1.8 KB
  against 306 B), while the handshake changes by fractions of a millisecond here.
- The hybrid costs the sum of its parts (X25519 + ML-KEM-768), the price of being safe if either one is broken.
- On the Pico W (finding 85, TLS handshakes): ML-KEM-512 / 768 / 1024 156-192 ms, X25519 258 ms, X25519MLKEM768
  284 ms.

</details>

## Step 5: the certificate types (mTLS)

```bash
for s in certs:8883 mldsa87:8886 ecdsa:8885; do d=${s%:*}; p=${s#*:}
  $T localhost $p 50 5 $d/CA.crt $d/client.crt $d/client.key > c.csv
  echo "$d: handshake $(med tls_ms < c.csv) ms; received $(med hs_rx_B < c.csv) B, sent $(med hs_tx_B < c.csv) B; verify $(med hs_verify_us < c.csv) us, sign $(med hs_sign_us < c.csv) us"
done
```

<details><summary>Answer</summary>

| Certificates | Handshake | Device receives | Device sends | Verify | Sign |
|---|---|---|---|---|---|
| ML-DSA-44 (`certs`, ours) | 4.48 ms | 7,881 B | 7,944 B | 312 µs | 562 µs |
| ML-DSA-87 | 6.49 ms | 13,579 B | 13,649 B | 853 µs | 956 µs |
| ECDSA P-256 | 3.79 ms | 1,938 B | 1,984 B | 290 µs | 46 µs |

- ML-DSA-44 moves 4× the bytes of ECDSA; ML-DSA-87 7×. That's why the project uses the smallest set, ML-DSA-44 (NIST
  security category 2), on the device.
- On the Pico W the signing gap is much bigger: ML-DSA-44 0.16 s, ML-DSA-87 0.36 s, ECDSA P-256 43 ms (finding 85).

</details>

## Step 6: protecting each frame (labs 6-7)

```bash
mmed() { awk -F, -v c=$1 '$1=="msg" && $2~/^[0-9]+$/ {print $c}' | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
for a in lorawan10 lorawan11 lorawan11_256 lorawan11_e2e aes256gcm; do
  AEAD=$a MSGS=50 $T localhost 8883 1 0 certs/CA.crt certs/client.crt certs/client.key > a.csv
  echo "$a: seal $(mmed 4 < a.csv) us, open $(mmed 6 < a.csv) us, through the broker and back $(mmed 5 < a.csv) us, $(mmed 7 < a.csv) B on the socket"
done
```

Each run is one mTLS connection that sends 50 readings, each sealed (`seal_us`), sent through the broker, received
back and opened (`open_us`).

<details><summary>Answer</summary>

| Scheme | Seal | Open | Bytes on the socket per message |
|---|---|---|---|
| `lorawan10` | 0.5 µs | 1.5 µs | 103 |
| `lorawan11` | 0.7 µs | 1.0 µs | 103 |
| `lorawan11_256` | 0.7 µs | 1.5 µs | 103 |
| `lorawan11_e2e` | 1.4 µs | 2.5 µs | 107 |
| `aes256gcm` | 0.5 µs | 0.6 µs | 115 |

- On a laptop, a frame costs about a microsecond: next to a 4 ms handshake, nothing.
- On the Pico W (finding 119), `lorawan11_e2e` seals an uplink in 926-945 µs against 772-797 µs for `lorawan11`:
  the 256-bit layer costs about **150 µs per uplink** there. A LoRa radio then spends **2.8 s** of airtime on a 64-byte
  frame at the slowest data rate. On the air, the bytes matter far more than the crypto.

</details>

## What to take away

- Post-quantum TLS costs **bytes** on every machine; it costs **time** mostly on small devices.
- Measure on the device you'll deploy: the same mTLS handshake is about 5 ms here, 20 ms on a Pi 4 and 500 ms on a
  Pico W.
- The project's full results, per device and per algorithm: `docs/findings.md` (83, 85, 119).
