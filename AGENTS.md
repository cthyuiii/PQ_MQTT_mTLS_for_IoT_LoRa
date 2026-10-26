# AGENTS.md

ChirpStack (LoRaWAN network server) with post-quantum TLS: TLS 1.3, X25519MLKEM768, ML-DSA-44 certificates on both
sides, then AES-256 LoRaWAN session keys. What runs and how: `README.md`. Status: `docs/pending.md`. Results:
`docs/findings.md`. The testbed (two Pis, Home Assistant as the application): `docs/testbed.md`.

## Layout

- `network/`: the broker (`mqtt_bench.py --role broker`), the host device tool (`mqtt_tls_timer.c`, `app_aead.c`),
  the virtual gateway, the stand-in application. `network/chirpstack` is a submodule (our fork, branch `iot-pqc`):
  change it there, then commit the new pointer here.
- `scripts/`: certificates (`gen_certs.sh`), ChirpStack's setup (`chirpstack_pq_setup.sh`), start/stop (`broker.sh`,
  `app.sh`), the AES-256 LoRaWAN vectors (`aes256_vectors.sh`), the Dockerfiles.
- `pico/`: the Pico W firmware (`sketches/`), its runner (`run_benchmarks.py`) and host tests (`tests/`).

## Build and test

Needs OpenSSL 3.5+ (Debian 13, or Homebrew `openssl@3` on macOS; not Apple's LibreSSL). The same as CI:

```bash
bash network/build_timer.sh openssl
AEAD=lorawan11_256 MSGS=1 AIR=1 network/mqtt_tls_timer 127.0.0.1 9 1 0
python3 network/virtual_gateway.py --selftest
python3 network/chirpstack_app.py --selftest
bash scripts/aes256_vectors.sh
ruff check . && git ls-files '*.sh' | xargs shellcheck -S error
```

Not in CI: `pico/tests/mqtt_parse_test.py` (needs `certs/MLDSA44` and `certs/round3/SNOVA1K`),
`pico/tests/aead_host_test/run.sh` (needs the arduino-pico core), anything with a Pi, a Pico or ChirpStack's images.

## Rules

- No plain MQTT anywhere, not even on loopback or inside Docker. Plain UDP only from the device to the virtual
  gateway and from the packet forwarder to the Gateway Bridge (the same machine).
- The broker offers X25519MLKEM768 only: mTLS on :18835, TLS with a login on :18935 (the application). Don't add a
  classical group, a plain listener or anonymous access outside `BROKER_BENCH=1`.
- Never commit `certs/`, keys, passwords, Wi-Fi details (`WIFI_SSID`, `WIFI_PASS`) or `results/`. Never print a key
  or a password. `CA.key` and `ClientCA.key` stay on the CA's machine.
- Run `scripts/broker.sh` as a normal user, not with sudo (Mosquitto 2 would drop to its own user and fail to read
  the 0600 files).
- README explains the code only. Measurements and conclusions go in `docs/findings.md`, progress in
  `docs/pending.md`.
- Versions are part of the results: `requirements.txt` and the Docker base images are pinned on purpose. Upgrade on
  purpose, rerun, and record it.
- Commits: conventional prefixes (`feat:`, `fix:`, `docs:`, `chore:`) so release-please can write the changelog.