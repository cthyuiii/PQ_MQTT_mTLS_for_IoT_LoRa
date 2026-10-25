# IoT-PQC — onboarding: post-quantum TLS

**Branch `onboarding/learn`: learning material only.** Start at **[learn/README.md](learn/README.md)**: eight
hands-on labs, from "where do the algorithms come from" through the TLS handshake, LoRaWAN frames and our 256-bit layer,
to benchmarks. They run in a plain Debian container on any laptop; the only thing built is the project's MQTT client,
inside the container.

## The project in one paragraph

IoT devices (a Raspberry Pi Pico W over Wi-Fi), the LoRaWAN network server ChirpStack, and the application all talk
through one MQTT broker on a Raspberry Pi. Every link to that broker uses **post-quantum TLS**: TLS 1.3 with the hybrid
key exchange X25519MLKEM768 and ML-DSA-44 certificates on both sides (mutual TLS). Stock ChirpStack can't do that, so we
build it from a fork with a different crypto provider. Next: the LoRa gateway's link, then AES-256 LoRaWAN session keys.

## Branches

| Branch | What it is |
|---|---|
| `onboarding/learn` | this one: the labs, and the few project files they read |
| `feature/custom-chirpstack-server` | the prototype: the ChirpStack fork, its build and the scripts around it. Make your own branch from it for gateway / AES-256 work |
| `macc-personal/test&implementation` | macc's own test branch (please don't push); its `docs/pending.md` lists what's done and what's left |
| `main` | the benchmark suite: signatures, key exchange and TLS on a Mac, a Pi and the Pico W |
| `LoRa_1.1_implementation` | the earlier LoRaWAN 1.1 chain with the stock ChirpStack |

## Files on this branch

Only what the labs open. Everything else is on the prototype branch.

```text
├── learn/                      ← the labs: start at learn/README.md
├── docs/findings.md            ← the project's numbered findings (127-129: the ChirpStack and Gateway Bridge work)
├── network/
│   ├── chirpstack/             ← our ChirpStack fork, a git submodule (lab 1 reads its one commit)
│   ├── mqtt_bench.py           ← how the project's broker is configured (labs 3, 4 and 8)
│   ├── app_aead.{c,h}          ← LoRaWAN 1.0.x / 1.1 frames and the 256-bit layer (labs 6-8)
│   ├── mqtt_tls_timer.c        ← the project's MQTT client: TLS / mTLS timing, frames through the broker (labs 7-8)
│   └── hs_timing_openssl.c, wire_stats.h  ← its in-handshake crypto timing and byte counts (lab 8)
├── scripts/
│   ├── gen_certs.sh            ← how the project makes its CAs, keys and certificates (labs 2 and 5)
│   └── chirpstack_pq_setup.sh  ← ChirpStack's certificates and settings (lab 5)
└── pico/sketches/
    ├── wolfssl_bench/wolfssl_user_settings.h  ← the Pico W's wolfSSL settings (lab 1)
    └── mqtt_tls_bench/hs_timing.h             ← the timing columns, shared with the Pico's firmware (lab 8)
```

To fetch the submodule as well: `git clone --recurse-submodules -b onboarding/learn <repo URL>`, or
`git submodule update --init` in an existing clone.
