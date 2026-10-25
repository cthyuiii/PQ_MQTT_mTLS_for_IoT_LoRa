# Lab 3 — One handshake, message by message

The order, from the moment a device connects to the broker:

```mermaid
sequenceDiagram
    participant C as Client (device)
    participant S as Server (broker)
    C->>S: TCP SYN
    S->>C: SYN-ACK
    C->>S: ACK
    C->>S: ClientHello: key shares (ML-KEM-768 public key + X25519), signature schemes (mldsa44, ...)
    S->>C: ServerHello: ML-KEM ciphertext + X25519
    Note over C,S: both now hold the same secret; everything below is encrypted
    S->>C: EncryptedExtensions, CertificateRequest (mTLS)
    S->>C: Certificate (server.crt), CertificateVerify (ML-DSA signature), Finished
    C->>S: Certificate (client.crt), CertificateVerify (ML-DSA signature), Finished
    C->>S: MQTT CONNECT, PUBLISH ... (application data)
```

**The key exchange doesn't happen before TLS. It *is* the first two TLS messages.** The client sends an ML-KEM
public key; the server uses it to wrap a fresh secret and sends back the ciphertext; the client unwraps it with its
private key. X25519 runs alongside, and both results go into the session keys. The signatures come after that, already
encrypted.

All commands run in the container, in `/lab`, with lab 2's certificates.

## Step 1: a mutual-TLS server, and a traced client

```bash
cd /lab
openssl s_server -accept 4433 -cert certs/server.crt -key certs/server.key \
  -CAfile certs/ClientCA.crt -Verify 1 -tls1_3 -www > server.log 2>&1 &
```

`-Verify 1` makes it mutual TLS: the server asks for a client certificate and refuses a connection without one.

**Predict:** the ClientHello is the device's first TLS message. Roughly how big is it, and which key-exchange group
comes first?

```bash
openssl s_client -connect localhost:4433 -CAfile certs/CA.crt -cert certs/client.crt -key certs/client.key \
  -trace -keylogfile keys.log < /dev/null > trace.txt 2>&1
grep -E '^ +[A-Za-z]+, Length=|NamedGroup: |key_exchange: ' trace.txt | cut -c1-70
grep -E '^(Protocol|Cipher|Peer signature type|Verify return code)' trace.txt
```

<details><summary>Answer</summary>

```text
    ClientHello, Length=1524
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1216): 493B0BDD773E68893B0F02B62C9729F5A725A42
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): E53D806F329AF3BC7F7A0F747C94A9B6821A8A2A5
    ServerHello, Length=1206
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1120): 007B4BCD3B9801B41020DF95BFD04D49B464F6031
    EncryptedExtensions, Length=2
    CertificateRequest, Length=92
    Certificate, Length=3998
    CertificateVerify, Length=2424
    Finished, Length=48
    CompressedCertificate, Length=3997
    CertificateVerify, Length=2424
    Finished, Length=48
```

- **ClientHello, about 1.5 KB**, almost all of it one key share: X25519MLKEM768, **1,216 bytes** = the ML-KEM-768
  public key (1,184) + an X25519 key (32). A classical ClientHello is a few hundred bytes. The client also sends a
  plain X25519 share (32 bytes), in case the server doesn't know the hybrid; that saves a round trip.
- **ServerHello: 1,120 bytes** = the ML-KEM ciphertext (1,088) + the server's X25519 key (32).
- **CertificateVerify, 2,424 bytes** each way: an ML-DSA-44 signature (2,420) over everything sent so far. It proves
  the sender holds the private key of the certificate it just sent.
- **Finished:** a check value over the whole conversation. If anyone changed a byte on the way, it doesn't match.
- **CompressedCertificate** is the client's certificate, compressed (OpenSSL does it by default). Run the client
  again with `-no_tx_cert_comp` and it sends a plain `Certificate` of 3,978 bytes: compressing made it about 20 bytes
  *larger*. ML-DSA keys and signatures look random, and random data doesn't compress.
- `Protocol: TLSv1.3`, `Peer signature type: mldsa44`, `Verify return code: 0 (ok)`.

</details>

**Predict:** in one mutual-TLS handshake, how many ML-DSA signatures does each side **make**, and how many does it
**check**?

<details><summary>Answer</summary>

Each side makes **1** (its CertificateVerify) and checks **2**: the CA's signature inside the other side's certificate,
and the other side's CertificateVerify. The CA's private key does nothing during a handshake; it signed the
certificates long before. On top of that, the client makes an ML-KEM key pair and unwraps the ciphertext, and the
server wraps the secret. That's the work a Pico W does each time it connects.

</details>

## Step 2: what does the network see?

```bash
tcpdump -i lo -s 0 -w hs.pcap tcp port 4433 2>/dev/null & TP=$!
sleep 1
openssl s_client -connect localhost:4433 -CAfile certs/CA.crt -cert certs/client.crt -key certs/client.key \
  -keylogfile keys.log < /dev/null > /dev/null 2>&1
sleep 1; kill $TP
```

**Predict:** someone records this connection. Which messages can they read? Can they tell which device connected?

```bash
tshark -r hs.pcap 2>/dev/null | cut -c1-120 | head -12
```

<details><summary>Answer</summary>

The TCP handshake (`SYN`, `SYN, ACK`, `ACK`), then `Client Hello` and `Server Hello`, then only `Application Data`.
In TLS 1.3 the certificates travel **encrypted**, so a listener can't read the device's certificate, and with it its
name. (They do see the IP addresses and the key shares, which are useless without the private keys.)

</details>

Now give tshark the session secrets that `-keylogfile` saved:

```bash
tshark -r hs.pcap -o tls.keylog_file:keys.log 2>/dev/null | cut -c1-120 | head -12
```

The same packets now read `Encrypted Extensions, Certificate Request`, `Certificate, Certificate Verify, Finished`,
`Compressed Certificate`, and so on. A key log is how you debug your own connections; a real system never writes one.
To look inside each message, open the capture in Wireshark on your machine
(`docker cp pqc-lab:/lab/hs.pcap .` and the same for `keys.log`; Preferences → Protocols → TLS → (Pre)-Master-Secret
log filename).

## Step 3: MQTT on top

Our broker is Mosquitto with these settings (from `network/mqtt_bench.py`). Stop the test server and start a broker:

```bash
pkill -f s_server
cat > broker.conf <<'EOF'
listener 8883
tls_version tlsv1.3
cafile /lab/certs/ClientCA.crt
certfile /lab/certs/server.crt
keyfile /lab/certs/server.key
require_certificate true
use_identity_as_username true
allow_anonymous false
log_dest stdout
EOF
chown mosquitto certs/server.key      # the broker runs as its own user, and only it may read its key
mosquitto -c broker.conf > broker.log 2>&1 &
M="-h localhost -p 8883 --cafile certs/CA.crt --cert certs/client.crt --key certs/client.key"
mosquitto_sub $M -t 'lab/#' -v -C 1 &
sleep 1; mosquitto_pub $M -t lab/hello -m 'hi over PQ mTLS'
tail -4 broker.log
```

- `require_certificate true` + `allow_anonymous false`: mutual TLS, and nobody gets in without a certificate.
- `use_identity_as_username true`: the certificate's name (`lab-device`) becomes the MQTT user name. An access list
  (ACL) can then give each certificate its own topics.

**Predict:** `mosquitto_pub` sends one message. How many TLS handshakes does that cost?

<details><summary>Answer</summary>

One per run: `mosquitto_pub` connects, does the full handshake, sends CONNECT and PUBLISH, then disconnects. That's
why an MQTT device normally keeps one connection open and publishes many messages over it. The broker log shows each connection with
`u'lab-device'`, the name from the certificate.

</details>

Leave the broker running for [lab 4, break it on purpose](04-break-it.md).
