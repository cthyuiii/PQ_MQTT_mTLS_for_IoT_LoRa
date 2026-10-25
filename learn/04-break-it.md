# Lab 4 — Break it on purpose

Seven ways to fail a handshake. For each: **predict** whether it connects, **who** refuses (the device or the
broker), and **why**. Then run it, and read both sides: the client's error and the broker's log.

Uses lab 3's broker (port 8883) and certificates, in `/lab`. Watch the broker in a second terminal:
`docker exec -it pqc-lab tail -f /lab/broker.log`.

```bash
cd /lab
M="-h localhost -p 8883 --cafile certs/CA.crt"
```

## 1. No client certificate

```bash
mosquitto_pub $M -t lab/x -m x
```

## 2. A certificate from the wrong CA (same name, made by yourself)

```bash
openssl genpkey -algorithm ML-DSA-44 -out certs/rogue.key
openssl req -x509 -new -key certs/rogue.key -out certs/rogue.crt -days 30 -subj /CN=lab-device
mosquitto_pub $M --cert certs/rogue.crt --key certs/rogue.key -t lab/x -m x
```

## 3. The right broker at an address its certificate doesn't name

```bash
IP=$(hostname -I | awk '{print $1}')
mosquitto_pub -h $IP -p 8883 --cafile certs/CA.crt --cert certs/client.crt --key certs/client.key -t lab/x -m x
openssl s_client -connect $IP:8883 -verify_ip $IP -CAfile certs/CA.crt \
  -cert certs/client.crt -key certs/client.key < /dev/null 2>&1 | grep -E 'verify error'
```

## 4. The device trusts the wrong CA

```bash
mosquitto_pub -h localhost -p 8883 --cafile certs/ClientCA.crt --cert certs/client.crt --key certs/client.key -t lab/x -m x
```

## 5. An expired device certificate

```bash
openssl x509 -req -in certs/client.csr -CA certs/ClientCA.crt -CAkey certs/ClientCA.key \
  -not_before 20250101000000Z -not_after 20250102000000Z -out certs/expired.crt
mosquitto_pub $M --cert certs/expired.crt --key certs/client.key -t lab/x -m x
```

## 6. TLS 1.2

```bash
openssl s_client -connect localhost:8883 -tls1_2 -CAfile certs/CA.crt \
  -cert certs/client.crt -key certs/client.key < /dev/null 2>&1 | grep -E 'alert'
```

## 7. A classical-only client

```bash
openssl s_client -connect localhost:8883 -groups X25519 -CAfile certs/CA.crt \
  -cert certs/client.crt -key certs/client.key < /dev/null 2>/dev/null | grep -E 'Temp Key|group|Verify return'
```

<details><summary>Answers 1-6</summary>

| # | Connects? | Who refuses | The device sees | The broker logs |
|---|---|---|---|---|
| 1 | no | the broker | `The connection was lost.` | `peer did not return a certificate` |
| 2 | no | the broker | `The connection was lost.` | `certificate verify failed` |
| 3 | no | the device | `Protocol error` (with `-d`: `host name verification failed`; s_client: `IP address mismatch`) | `tlsv1 alert internal error` |
| 4 | no | the device | `Protocol error` | `tlsv1 alert unknown ca` |
| 5 | no | the broker | `The connection was lost.` | `certificate verify failed` |
| 6 | no | the broker | `alert protocol version` (alert 70) | `unsupported protocol` |

- **2:** a name means nothing without the CA's signature. Anyone can make a certificate that says `lab-device`.
- **3:** this is the error our ChirpStack hit with the Pi broker: the broker's certificate named only `localhost`
  and `127.0.0.1`, and rustls checks the name. The fix was a certificate that names the Pi's address
  (`gen_certs.sh --server-names`), not switching the check off.
- **4:** "who refuses" tells you which side's trust is wrong. Here the device refused the broker.
- **5:** checking dates needs a clock. wolfSSL on Arduino boards skips certificate dates by default; our Pico
  firmware checks them only when built with `-DWB_ASN_TIME` (its clock set from the network).
- **6:** the broker allows TLS 1.3 only (`tls_version tlsv1.3`). Even a broker that allowed 1.2 couldn't use these
  certificates or groups: ML-DSA in certificates and the ML-KEM groups are defined for TLS 1.3 only. Try it:
  `openssl s_server -accept 4434 -cert certs/server.crt -key certs/server.key -www &`, then
  `openssl s_client -connect localhost:4434 -tls1_2 -CAfile certs/CA.crt < /dev/null` fails with
  `alert handshake failure` (40).

</details>

<details><summary>Answer 7</summary>

**It connects:** `Peer Temp Key: X25519, 253 bits`, `Verify return code: 0 (ok)`. The certificates are still
ML-DSA, but the session key came from X25519 alone. Someone who records this connection today could decrypt it
later with a large enough quantum computer ("record now, decrypt later"). Post-quantum signatures can't prevent
that: they only matter while the connection is being set up.

A hybrid group protects you only if **the server insists on it**. Make this broker accept X25519MLKEM768 only:

```bash
pkill mosquitto
printf 'openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = sys\n[sys]\nGroups = X25519MLKEM768\n' > pq-only.cnf
OPENSSL_CONF=/lab/pq-only.cnf mosquitto -c broker.conf > broker.log 2>&1 &
sleep 1
openssl s_client -connect localhost:8883 -groups X25519 -CAfile certs/CA.crt \
  -cert certs/client.crt -key certs/client.key < /dev/null 2>&1 | grep -E 'alert'
openssl s_client -connect localhost:8883 -CAfile certs/CA.crt \
  -cert certs/client.crt -key certs/client.key < /dev/null 2>/dev/null | grep -E 'group'
```

Now the classical client gets `alert handshake failure` (40), and a normal client still gets
`Negotiated TLS1.3 group: X25519MLKEM768`.

**Discuss:** on 25 Oct the project's broker on the Pi still accepted an X25519-only client. ChirpStack and the
Pico get X25519MLKEM768 because they offer it first, not because the broker requires it. The reason: the broker
also serves the old benchmark's key-exchange sweep (`SWEEP_GROUPS` in `network/mqtt_bench.py`), which includes
classical groups. What should the final setup accept, and what would break if it changed?

</details>

Next: [lab 5, our system](05-our-system.md).
