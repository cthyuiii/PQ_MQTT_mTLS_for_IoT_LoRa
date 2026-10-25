# Lab 5 — Our system

## The architecture

```mermaid
flowchart LR
    lora["LoRa device"] -. "radio, LoRaWAN<br/>(planned)" .-> pf
    subgraph m1["Machine 1, Docker"]
        pf["packet forwarder<br/>(today: virtual_gateway.py)"] -- "UDP, inside<br/>this machine" --> gwb["Gateway Bridge<br/>Go 1.27"]
        cs["ChirpStack<br/>our build: rustls + aws-lc-rs"]
    end
    subgraph m2["Machine 2, a Pi"]
        broker["MQTT broker, port 18835<br/>Mosquitto + OpenSSL 3.5"]
    end
    gwb -- "PQ mTLS" --> broker
    cs -- "PQ mTLS" --> broker
    pico["Pico W<br/>Wi-Fi, wolfSSL"] -- "PQ mTLS" --> broker
    app["application<br/>chirpstack_app.py"] -- "PQ mTLS" --> broker
```

"PQ mTLS" = TLS 1.3, X25519MLKEM768, ML-DSA-44 certificates on both sides: labs 2 and 3, with these machines in
place of your container.

- **One broker in the middle.** Wi-Fi devices, the gateway, ChirpStack and the application all connect to it, and
  none of them connect to each other.
- **A LoRa device can't do TLS over the radio.** LoRaWAN's own AES protects that hop (labs 6 and 7), and TLS starts at
  the gateway. Between the packet forwarder (which drives the radio) and the Gateway Bridge the protocol is plain
  UDP, so both run on the same machine and that traffic never leaves it.
- **Today** the radio is simulated: `virtual_gateway.py` hands the gateway the frames a radio would have received. The
  gateway's link to the broker is the newest part (25 Oct).

One LoRa reading, from the device to the application:

```mermaid
sequenceDiagram
    participant D as LoRa device
    participant G as Gateway
    participant B as MQTT broker
    participant C as ChirpStack
    participant A as Application
    D->>G: radio: the LoRaWAN frame (AES, labs 6-7)
    G->>B: as923/gateway/{gateway}/event/up: the frame as received
    B->>C: the same message (ChirpStack subscribes to its gateways)
    Note over C: checks the MIC and the frame counter,<br/>removes the LoRaWAN layer
    C->>B: application/{app}/device/{DevEUI}/event/up
    B->>A: the same message
    Note over A: removes the inner 256-bit layer (lab 7)
```

Every arrow to or from the broker is its own PQ mTLS connection. The broker decrypts each message as it arrives and
encrypts it again for each subscriber.

## Who holds which key

| Private key | Lives on | Its certificate is signed by |
|---|---|---|
| `CA.key` | the CA's machine only: the copies to the others leave it out | (itself: it signed the broker's `server.crt`) |
| `ClientCA.key` | the CA's machine only | (itself: it signed every certificate below) |
| `server.key` | machine 2, the broker | `CA` |
| `client.key` (`pqc-client`) | built into the Pico W's firmware | `ClientCA` |
| `gateway.key` | machine 1, the Gateway Bridge (in seed-only form, lab 2) | `ClientCA` |
| `chirpstack.key` | machine 1, inside ChirpStack's container | `ClientCA` |
| `application.key` | wherever the application runs (machine 2 in the test bed) | `ClientCA` |

All of them are made on the CA's machine (`scripts/gen_certs.sh`, `scripts/chirpstack_pq_setup.sh`) and copied out.
That's fine for a test bed. In a deployment each device makes its own key and sends only a CSR, as you'll do below.

## Check yourself

1. TLS ends at the broker. Who can read a Pico's message in plain text?
2. Which links are post-quantum today, and which aren't?
3. Someone breaks into the Pi. What do they get, and what don't they get?

<details><summary>Answers</summary>

1. **The broker.** TLS protects each link, not the whole path: the broker decrypts what arrives and re-encrypts it
   for each subscriber. That's why the LoRa data carries an inner 256-bit layer that only the application can open;
   ChirpStack and the broker pass it on without the key.
2. Post-quantum: every MQTT link, Pico, gateway, ChirpStack and application ↔ broker (though the broker also accepts
   classical clients, lab 4 #7). Not post-quantum: the radio hop (LoRaWAN's AES-128 with our 256-bit layer inside;
   AES-256 LoRaWAN is planned), and the UDP from the packet forwarder to the Gateway Bridge, which isn't encrypted at
   all but never leaves machine 1.
3. They get `server.key` (they can pretend to be the broker until its certificate is replaced) and every message that
   passes through while they're in. The application runs on that Pi too, so they also get `application.key` and the
   inner layer's key. And because the test bed copies `certs/` whole, they'd find a copy of the Pico's `client.key`;
   in a deployment that key would exist only on the device. They **don't** get the CA keys, which stay on the CA's
   machine, so they can't issue themselves new certificates.

</details>

## Your own certificate on the real broker (on site, on the lab network)

The real CSR flow: your private key never leaves your container.

```mermaid
sequenceDiagram
    participant Y as You, in the container
    participant M as macc, who holds ClientCA.key
    participant B as The broker
    Note over Y: makes me.key and me.csr
    Y->>M: me.csr only: your name and public key
    Note over M: checks the CSR's signature,<br/>signs it with ClientCA.key, for 7 days
    M->>Y: me.crt, and the broker's CA.crt
    Y->>B: PQ mTLS with me.crt and me.key
```

**1. You:** make a key and a CSR, and copy the CSR out.

```bash
cd /lab
openssl genpkey -algorithm ML-DSA-44 -out me.key
openssl req -new -key me.key -subj /CN=learn-<your name> -out me.csr
exit                                   # then, on your laptop (PowerShell, Terminal or any shell):
docker cp pqc-lab:/lab/me.csr learn-<your name>.csr
```

Send `learn-<your name>.csr` to macc. Only the CSR.

<details><summary>2. macc: check and sign it (the machine with the client CA's key, repo root)</summary>

With OpenSSL 3.5 or newer:

```bash
C=certs/MLDSA44
openssl req -in learn-<name>.csr -noout -verify -subject
openssl x509 -req -in learn-<name>.csr -CA $C/ClientCA.crt -CAkey $C/ClientCA.key -CAcreateserial -days 7 -out learn-<name>.crt
```

Send back `learn-<name>.crt` and `certs/MLDSA44/CA.crt`. Seven days, because the broker has no revocation list
switched on yet (the CRL is paused): a certificate can't be taken back, only left to expire.

</details>

**3. You:** copy them in (from your laptop), then connect to the real broker.

```bash
docker cp learn-<your name>.crt pqc-lab:/lab/me.crt
docker cp CA.crt pqc-lab:/lab/broker-CA.crt
docker start -ai pqc-lab
cd /lab
B="-h 192.168.50.133 -p 18835 --cafile broker-CA.crt --cert me.crt --key me.key"
mosquitto_sub $B -t 'pqc/learn/#' -v &
sleep 2; mosquitto_pub $B -t pqc/learn/<your name> -m "hello from <your name>"
openssl s_client -connect 192.168.50.133:18835 -CAfile broker-CA.crt -cert me.crt -key me.key -trace \
  < /dev/null 2>&1 | grep -E '^ +[A-Za-z]+, Length=|NamedGroup: |^Verify return' | cut -c1-70
```

You see everyone's `pqc/learn/` messages, and the same handshake as lab 3, now with the Pi. Keep to `pqc/learn/`:
the broker's access list (ACL) is paused too, so it won't stop you from writing anywhere else.

## Where to go next

- [Lab 6, a LoRaWAN frame byte by byte](06-lorawan-frame.md): what protects the radio hop, where TLS can't.

- `docs/findings.md` 127-129: the ChirpStack and Gateway Bridge work, with the captures.
- The open work (gateway, AES-256 LoRaWAN, the broker's group list): `docs/pending.md` on
  `macc-personal/test&implementation`.
