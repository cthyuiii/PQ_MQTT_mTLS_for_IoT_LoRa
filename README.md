# IoT-PQC — post-quantum cryptography for IoT / LoRaWAN (SIT Topic C)

Benchmarks for everything Topic C compares, on a MacBook, a Raspberry Pi 4/5 and a Pico W / Pico 2 W:
PQC signatures and key exchange, payload protection (real LoRaWAN AES-CTR + CMAC, AES-GCM, Ascon),
TLS / mutual-TLS handshakes with PQ certificates, MQTT over them, and the full pipeline from PQ
handshake to protected payload to MQTT broker. `./run_all.sh` runs all of it (§0). §0.2 says what each
bench measures and with which code, §0.3 describes the pipeline and LoRaWAN framing.
[docs/how_it_works.md](docs/how_it_works.md) has the test plan per device, every stage's function calls in order, and
how LoRaWAN, AES, Ascon, GCM and CMAC relate. What the benches found is in [docs/findings.md](docs/findings.md).

```text
PQ_MQTT_mTLS_for_IoT_LoRa/
├── run_all.sh                     ← ONE command for every bench (Mac / Pi; + Pico when plugged in)
├── requirements.txt               ← pyserial (the Pico runner); every timed stage is C
├── docs/
│   ├── how_it_works.md            ← test plan per device, each stage's calls, LoRaWAN / AES / Ascon explained
│   ├── findings.md                ← what the benches found (numbered findings, sources, future work)
│   └── pico_build_notes.md        ← how each Pico sketch was ported / what failed and why
├── scripts/
│   ├── gen_certs.sh               ← CA + server + client certificate per signature → certs/<SIG>/
│   └── collate_results.py         ← every result file → results/all_results.csv
├── signatures/                    ← Stage 1: keygen / sign / verify
│   ├── sig_speed.c                ← one C bench for OpenSSL, liboqs (-DSIG_LIBOQS) and wolfSSL (-DSIG_WOLFSSL)
│   ├── to_customer_form.py        ← the customer's table (stage1_customer_form_<tag>.csv)
│   └── reference/                 ← NIST submission code: HAWK, SDitH, QR-UOV, FAEST, SQIsign
├── network/                       ← everything measured through the MQTT broker
│   ├── mqtt_tls_timer.c           ← MQTT client: plain / TLS / mTLS connect, the pipeline, the KEM exchange (OpenSSL or wolfSSL)
│   ├── app_aead.{c,h}             ← the pipeline's LoRaWAN 1.0.x / 1.1 frames (up / down), AES-GCM, Ascon, self-test
│   ├── wire_stats.h               ← socket writes / reads and TCP segments, for the on-wire byte estimate
│   ├── mqtt_bench.py              ← Stage 2 + pipeline + KEM exchange driver (one Mosquitto per certificate)
│   ├── tls_sweep.sh               ← TLS / mTLS key-exchange sweep: MQTT connections to the broker's listeners
│   ├── provenance.py              ← board name + versions record
│   └── build_ascon.sh, build_timer.sh, build_wolfssl.sh
├── pico/                          ← Pico W (RP2040) / Pico 2 W (RP2350), flashed from the Mac
│   ├── run_benchmarks.py          ← compile, flash, read serial, merge into logs/results.csv
│   ├── sketches/                  ← one Arduino sketch per folder (folder name = .ino name)
│   │   ├── mldsa_bench/ falcon_bench/ slhdsa_bench/ hawk_bench/ faest_bench/ sdith_bench/
│   │   │                          ← one folder per family; -DPICO_VARIANT_<set> picks the parameter set
│   │   ├── liboqs_bench/          ← liboqs bare-metal: 0.16 (the host liboqs stage's code) and liboqs main for the
│   │   │                            round 3 MAYO / SNOVA / MQOM / UOV sets; keccak_swap.sh = optional XKCP Keccak
│   │   ├── wolfssl_bench/         ← wolfSSL 5.9.4: ML-DSA, SLH-DSA, ECDSA, Ed25519, RSA, Falcon
│   │   ├── mqtt_tls_bench/        ← Pico W: MQTT over TLS / mTLS (wolfSSL) + the pipeline; lora_aead.h = LoRaWAN
│   │   │                            1.0.x / 1.1, AES-128/256-GCM (BearSSL), Ascon (M0 assembly), via the broker
│   │   ├── rsa_bench/ ecdsa_bench/ ← classical baselines (BearSSL), the same -DPICO_VARIANT_<set> scheme
│   │   └── ed25519_bench/ ed448_bench/ qruov_zoo_bench/ (-D parameters) uov1_bench/ (UOV-Ip, keys in flash)
│   ├── tests/                     ← aead_host_test, kem_host_test (Pico code vs the host's, on the Mac),
│   │                                mqtt_parse_test.py (log → all_results.csv), qemu_liboqs (Keccak swap in QEMU)
│   └── logs/, logs_<tag>/         ← results.csv (customer's form) + one .log per sketch; logs_<tag>: --tag runs
└── certs/   results/              ← made by the runs (gitignored)
```

## 0.  Quick start: one command per device

`./run_all.sh` runs every stage the machine can run and writes to `results/` with a `_mac` / `_pi`
suffix (override with `TAG=`). Each stage is independent: one that fails is logged and the next one
runs. Builds that should not live in iCloud (wolfSSL, liboqs, BearSSL for the host test) go to
`~/.cache/iot-pqc`.

**Pinned versions** (28 Sep 2026). Change one on purpose, re-run, and let `versions_<tag>.json` record it; it
records the versions each run actually used.

| Area | Component | Version |
|---|---|---|
| Mac host | macOS / CPU / compiler | macOS 26.6.2 (25G83), Apple M1 Pro, Apple clang 21.0.0 |
| | Homebrew / build tools | Homebrew 7.0.6; cmake 4.4.3, autoconf 2.73, automake 1.19, libtool 2.6.2 |
| TLS / MQTT | OpenSSL | 3.6.4 (Homebrew `openssl@3`) |
| | Mosquitto | 2.1.2 (linked to that OpenSSL 3.6.4) |
| PQC | liboqs | 0.16.0 (tag, commit `5a1a854`): one build in `~/.cache/iot-pqc/liboqs-host` for the `liboqs` stage (C) and oqs-provider; the same release is cross-compiled for the Pico (ML-DSA, Falcon, SLH-DSA) |
| | oqs-provider | commit `c174ed7` (0.12.0-dev, 12 Sep 2026), built against that liboqs 0.16.0 |
| | round 3 pair (MAYO, SNOVA, MQOM, UOV) | oqs-provider `36cafae` (19 Sep 2026) on liboqs main `b196b57a` (`0.16.0-50`, 24 Sep 2026), built by `run_all.sh` in `~/.cache/iot-pqc/{liboqs-r3,oqs-provider-r3-build}`; the same liboqs commit is cross-compiled for the Pico (`LIBOQS_ROUND=3`) |
| | wolfSSL | 5.9.4 (`v5.9.4-stable`, Mac, Pi and Pico) |
| AEAD | ascon-c | commit `446347f` (`CRYPTO_VERSION` 1.3.0, NIST SP 800-232) |
| Python | interpreter | 3.14.7 (Homebrew; venv `.venv.nosync`, linked as `.venv`) |
| | packages (`requirements.txt`) | pyserial 3.5 (the Pico runner); nothing else: every timed stage is C |
| Pico | Arduino | arduino-cli 1.5.1; arduino-pico core `rp2040:rp2040` 6.1.1 |
| | toolchain / SDK | pqt-gcc 5.0.0-9576866 = GCC 16.1.0, newlib 4.6.0; Pico SDK 2.3.0; BearSSL as bundled in the core |
| | other | rweather Crypto 0.4.0 (Ed25519 sketch); XKCP commit `4affab4` (optional Keccak) |
| Checks | QEMU | 11.1.1 (`pico/tests/qemu_liboqs`) |
| Pi | everything | recorded by `versions_<tag>.json` at run time (Pi OS Trixie: OpenSSL 3.5.x, Python 3.13) |

Held back on purpose:
- **oqs-provider `36cafae`** ("round-3 MAYO / MQOM / SNOVA") needs unreleased liboqs: against 0.16.0 it
  fails to build with 180 errors. So it doesn't replace the pinned pair. The `round3` stage builds it
  with liboqs main *beside* the pinned pair and loads it only for the round 3 sets. MAYO, SNOVA, MQOM and
  UOV run only as their round 3 sets (round 3 changed MAYO-1/2 and UOV-Ip/III/V, replaced SNOVA's sets and
  moved MQOM to v3): from this pair on the Mac / Pi, from the same liboqs commit on the Pico. Everything
  else stays on liboqs 0.16.0 / `c174ed7`.
- `./run_all.sh --dry-run` flags an oqs-provider source that doesn't match its build.

**MacBook (Apple Silicon)**

```bash
git clone https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git && cd PQ_MQTT_mTLS_for_IoT_LoRa
brew install python@3.14 openssl@3 cmake mosquitto autoconf automake libtool arduino-cli qemu
# the venv lives in .venv.nosync: iCloud Drive skips *.nosync (it had corrupted a synced .venv); .venv links to it
python3.14 -m venv .venv.nosync && ln -sfn .venv.nosync .venv && source .venv/bin/activate
pip install -r requirements.txt
# liboqs 0.16.0, built once where run_all.sh looks for it (its liboqs stage then skips the build)
C=~/.cache/iot-pqc && git clone -q --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git $C/liboqs-src
cmake -S $C/liboqs-src -B $C/liboqs-build-host -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX=$C/liboqs-host \
      && cmake --build $C/liboqs-build-host --target install
# oqs-provider (Falcon inside OpenSSL), pinned, against that same liboqs; run_all.sh builds the round 3 pair itself
git clone -q https://github.com/open-quantum-safe/oqs-provider.git && git -C oqs-provider checkout -q c174ed7
cmake -S oqs-provider -B oqs-provider/build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
      -Dliboqs_DIR=$C/liboqs-host/lib/cmake/liboqs && cmake --build oqs-provider/build
./run_all.sh --dry-run && ./run_all.sh --no-deps  # everything (Pico too, if one is plugged in)
sudo -E ./run_all.sh --no-deps --only openssl     # optional: real cycle counts need root on macOS
```

**Raspberry Pi 4 / 5 (Raspberry Pi OS Trixie, 64-bit: ships OpenSSL 3.5)**

```bash
sudo apt update && sudo apt install -y git python3-venv build-essential cmake libssl-dev
git clone https://github.com/cthyuiii/PQ_MQTT_mTLS_for_IoT_LoRa.git && cd PQ_MQTT_mTLS_for_IoT_LoRa
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
C=~/.cache/iot-pqc && git clone -q --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git $C/liboqs-src
cmake -S $C/liboqs-src -B $C/liboqs-build-host -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX=$C/liboqs-host \
      && cmake --build $C/liboqs-build-host --target install
git clone -q https://github.com/open-quantum-safe/oqs-provider.git && git -C oqs-provider checkout -q c174ed7
cmake -S oqs-provider -B oqs-provider/build -DCMAKE_BUILD_TYPE=Release -Dliboqs_DIR=$C/liboqs-host/lib/cmake/liboqs \
      && cmake --build oqs-provider/build
./run_all.sh --dry-run && TAG=pi4 ./run_all.sh     # installs missing apt packages (never upgrades), then every stage
# Bookworm (OpenSSL 3.0) or the customer's build instead:
#   OPENSSL_PREFIX=/opt/openssl-3.5 MOSQUITTO=/opt/mosquitto-oqs/sbin/mosquitto TAG=pi4 ./run_all.sh
```

**Pico W (RP2040) / Pico 2 W (RP2350)**, flashed and read from the Mac:

```bash
arduino-cli config add board_manager.additional_urls \
    https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json
arduino-cli core update-index && arduino-cli core install rp2040:rp2040@6.1.1
arduino-cli lib install Crypto             # Ed25519 sketch (rweather Crypto)
# plug the Pico in (brand-new board: hold BOOTSEL while plugging); board type is auto-detected
./run_all.sh --no-deps --only pico         # = python3 pico/run_benchmarks.py
# Stage 2 + pipeline on the Pico W / Pico 2 W over Wi-Fi (the broker: ./run_all.sh --serve-broker in another terminal)
export WIFI_SSID="<your SSID>"; read -rs WIFI_PASS; export WIFI_PASS   # typed, so the password stays out of history
BROKER=<this Mac's LAN IP> python3 pico/run_benchmarks.py --test mqtt
```

All results in one CSV: `run_all.sh` (and the Pico runner) finish by running `python3 scripts/collate_results.py`,
which writes `results/all_results.csv`. Each row has platform, run, stage, library, algorithm, mode,
group, payload scheme, payload bytes, operation, metric, value, unit, n, status and source file. It
covers every stage's results, the Pico's and the QEMU counts. `results/` is gitignored, so use
`git add -f` to commit a CSV.

Pico results: `pico/logs/results.csv` (the customer's form + a `Library` column; a re-run replaces
only its own rows), one `.log` per sketch. The Pico W's MQTT runs (Stage 2 and the LoRaWAN / AES / Ascon
pipeline, through the broker) go to `results/{mqtt_mtls,pipeline}_*_pico_<board>.*`, in the host's columns.

## 0.1  Commands, by what you want to run

- `--quick` is a smoke test, not a result. It runs every stage with a few iterations (about 5 minutes
  on the Mac), so a missing tool or a broken stage shows up before a long run. That matters most the
  first time on a new machine such as the Pi. Its files carry a `_quick` suffix; the full run is the one
  to report.
- `--no-deps` skips the brew / apt step at the start. That step only installs what's missing and never
  upgrades what's installed (plain `brew install` would upgrade). Skip it once everything is installed,
  or when you have no sudo on a Pi.

Filters combine and work on the Mac, the Pi and (through the `pico` stage) the Pico. Names match
case- and punctuation-insensitively as substrings: `mldsa` = every ML-DSA set, `ml-dsa-44` = one.
A run with `--algo` / `--lib` writes `*_<tag>_partial` files, so it never overwrites a full run.

```bash
./run_all.sh --dry-run                         # prerequisites + the stages that would run; runs nothing
./run_all.sh --quick                           # every stage, a few iterations, *_<tag>_quick files (minutes)
./run_all.sh                                   # everything this machine can run
./run_all.sh --no-deps                         # the same without the brew / apt step (see below)
./run_all.sh --no-watch                        # without the independent subscribers (see "Watching" below)
SIG_N=50 ./run_all.sh --test pqc               # Stage 1 iterations, the same for every algorithm (default 100)
python3 scripts/collate_results.py                     # rebuild results/all_results.csv from every result file
./run_all.sh --only openssl,mtls               # named stages (list in §0.2 and run_all.sh's header)
```

**PQC signatures (Stage 1)**: OpenSSL (+ oqs-provider), liboqs, wolfSSL, NIST reference code, Pico

```bash
./run_all.sh --test pqc                        # every library, every algorithm (+ Pico if plugged in)
./run_all.sh --lib liboqs                      # one library: openssl | liboqs | wolfssl | reference | ...
./run_all.sh --algo ml-dsa-44,falcon-512       # these algorithms, every library
./run_all.sh --test pqc --lib liboqs --algo mayo    # combine: round 3 MAYO via liboqs main (host + Pico)
signatures/liboqs_sig_speed 200 ML-DSA-44 Falcon-512   # the liboqs stage's C program, by hand (liboqs names)
```

**AES, Ascon and real LoRaWAN (payload protection)**: measured only as messages through the MQTT broker, in the
pipeline (below). Checks that need no network:

```bash
bash pico/tests/aead_host_test/run.sh          # the Pico's LoRaWAN / AES / Ascon frames == the host's, byte for byte
```

**TLS and mTLS key-exchange sweep**: every certificate × key exchange (17 groups), as full MQTT connections to the
broker machine's TLS / mTLS listeners (`./run_all.sh --serve-broker` there), like Stage 2

```bash
./run_all.sh --broker <broker IP> --only tls   # -> results/tls_handshake_pure_<tag>_remote.csv + _meta
./run_all.sh --broker <broker IP> --only tls --algo mldsa44,ecdsap256
TLS_ITERS=500 ./run_all.sh --only tls
```

**MQTT over plain / TLS / mTLS with PQ certificates (Stage 2)**: X25519MLKEM768 fixed, Mosquitto

```bash
./run_all.sh --only mtls                       # OpenSSL + wolfSSL clients, every certificate
./run_all.sh --only mtls --algo mldsa44 --lib wolfssl
python3 network/mqtt_bench.py --modes tls,mtls --match falcon
python3 network/mqtt_bench.py --role broker                        # on the broker Pi
python3 network/mqtt_bench.py --role client --host <broker> --tag pi4
```

**Round 3 MAYO / SNOVA / MQOM / UOV**: oqs-provider `36cafae` + liboqs main, beside the pinned pair

```bash
./run_all.sh --only round3                     # Stage 1 (OpenSSL 16 sets, liboqs 34) + Stage 2 (4 MAYO, 9 SNOVA certificates)
./run_all.sh --only round3 --test pqc --algo snova   # Stage 1 only, SNOVA only
./run_all.sh --only round3 --lib liboqs --algo uov   # liboqs directly: round 3 UOV (oqs-provider has none)
```

- The first run builds the pair once: about 1 minute on the Mac.
- Stage 1 writes `openssl_sig_speed_r3_<tag>.{csv,meta}` (OpenSSL + the round 3 provider) and
  `liboqs_sig_speed_r3_<tag>.{csv,meta}` (`sig_speed.c -DSIG_LIBOQS` on liboqs main: MAYO, SNOVA,
  MQOM v3 constant-time sets, UOV). Both go into the Stage 1 table, with the library and commit in `Library`.
- Stage 2 writes `mqtt_mtls_*_<tag>_r3`, with certificates in `certs/round3/`: 4 MAYO and 9 SNOVA
  sets, and all 13 connect over TLS and mTLS. It uses the OpenSSL client only, because wolfSSL has no
  MAYO or SNOVA.
- `versions_<tag>_r3.json` records the provider and `liboqs_round3`. The provider's own build info still
  says "liboqs 0.16.0", because liboqs main hasn't bumped its version.

**Everything but signatures goes through the MQTT broker on another machine** (`tls`, `mtls`, `pipeline`, and
`round3`'s Stage 2)

Only signatures (Stage 1, the Pico signature sketches, the QEMU counts) are measured on one machine. TLS / mTLS
handshakes, key exchange, and LoRaWAN / AES / Ascon messages are measured only as MQTT traffic through a broker on
another machine. These stages run only with `--broker IP`; `collate_results.py` leaves out any run whose broker
was on the same machine, including one reached through this machine's own LAN address.

```bash
# 1. the broker machine (here the Mac): Mosquitto for every stage on all interfaces, until Ctrl-C
./run_all.sh --serve-broker                    # ends with: ./run_all.sh --broker 192.168.50.131
                                               # then one line per connection: client IP, certificate, TLS / mTLS
./run_all.sh --serve-broker --watch            # + every message routed (a second delivery: not for timing runs)
# 2. both machines need the same certs/. Run rsync ON THE MAC, from the repo root, in either case:
rsync -a --delete certs/ <pi-user>@<pi-ip>:PQ_MQTT_mTLS_for_IoT_LoRa/certs/    # Mac is the broker: push to the Pi
rsync -a --delete <pi-user>@<pi-ip>:PQ_MQTT_mTLS_for_IoT_LoRa/certs/ certs/    # Pi is the broker: pull from the Pi
# 3. the client machine (here the Pi), in its repo root
./run_all.sh --broker 192.168.50.131 --dry-run # reachable? certs/ = the broker's?
./run_all.sh --broker 192.168.50.131           # full run; or --test mqtt,pipeline for the MQTT part only
# the Pico W against the Pi's brokers (Pi: ./run_all.sh --serve-broker), kept apart from the Mac-broker run:
PICO_ARGS="--tag pi_broker" ./run_all.sh --only pico --test mqtt --broker <pi-ip>
```

- **The rsync placeholders.**
  - `<pi-user>` is the Pi's login name, the one you chose in Raspberry Pi Imager (there is no default
    `pi` user any more).
  - `<pi-ip>` is its address: `hostname -I` on the Pi, or its `.local` name, e.g. `raspberrypi.local`.
  - `PQ_MQTT_mTLS_for_IoT_LoRa` is the repo on the Pi. It is relative to that user's home directory, as `git clone` in its home
    makes it. Give the full path if yours lives elsewhere.
- **Why rsync runs on the Mac.** The Pi runs SSH, but the Mac only does when Remote Login is on (System
  Settings → General → Sharing), and it is off here.
- **Why `--delete`.** It makes the copy exact, so no stale certificate with another CA stays behind.
- **After the copy.** `certs/` includes `certs/round3/`. Re-copy whenever the broker machine regenerates
  its certificates.

- **What it covers.** Every network run: the `tls` sweep, `mtls`, `pipeline` with its watchers, round 3's
  Stage 2, and the Pico W's `mqtt_tls_bench`.
- **Results.** Files get a `_remote` suffix, and each meta file records the broker's address.
- **Ports.** Plain MQTT (the reference row) is on 18830. Each signature `i` has mTLS on
  18831+i and TLS on 18931+i. The round 3 set starts at 20830.
- **Firewall.** The broker machine must accept connections on these ports. The first time the Mac
  serves, macOS may ask whether to allow incoming connections for Mosquitto: allow it.
- **Certificates.** They name `localhost`, but the clients verify only the chain, not the host name, so
  any IP works. What must match is the CA, hence the copy. On the client, `run_all.sh` never generates
  certificates while `--broker` is set.
- **Records.** Each client meta file records `role: client` and `broker: <ip>:18830`. The broker machine
  writes `versions_<tag>_broker.json` (its Mosquitto, OpenSSL and providers).
- **Key exchange.** The Stage 2 listeners accept all 17 of the `tls` sweep's groups; every client offers
  exactly one, so Stage 2 always uses X25519MLKEM768.

**Full pipeline**: PQ handshake → LoRaWAN / AES-GCM / Ascon payload → MQTT broker → subscriber. The only place
LoRaWAN / AES / Ascon are measured, as uplink and downlink frames (`--dirs up,down`, both by default).

```bash
./run_all.sh --broker <IP> --test pipeline     # ECDSA-P256, ML-DSA-44, Falcon-512 x 6 payload schemes x up / down
PIPE_MSGS=1000 ./run_all.sh --only pipeline --algo mldsa44,lorawan10,aes128gcm
python3 network/mqtt_bench.py --messages 200 --modes mtls \
    --aeads lorawan10,lorawan11,aes128gcm,ascon --payload 51 --suite TLS_AES_128_GCM_SHA256
# watch it: an independent subscriber per broker prints each message as received, decrypted
python3 network/mqtt_bench.py --messages 5 --sigs MLDSA44 --watch
```

**Watching** is on for every `run_all.sh` pipeline run: the subscribers write
`results/pipeline_watch_<tag>.log`, and the run log reports "received N of N messages".

A watcher is a second delivery for the broker: it adds a few µs of broker work per message, small against a
network round trip of milliseconds. Handshake and seal / open times are unaffected. Use `--no-watch` for runs
where that round trip is the number you report.

**Pico only** (from the Mac; `--list` shows the selection without flashing)

```bash
python3 pico/run_benchmarks.py --lib liboqs --match ml-dsa --list
BROKER=<ip> python3 pico/run_benchmarks.py --test mqtt       # Pico W: MQTT / TLS / mTLS + the LoRaWAN / AES /
                                                                 # Ascon pipeline, up + down (WIFI_SSID, WIFI_PASS exported)
python3 pico/run_benchmarks.py --lib wolfssl,liboqs --match falcon,slh-dsa-sha2-128f
python3 pico/run_benchmarks.py --only mldsa_bench --match ml-dsa-44 --board rp2040
PICO_ARGS="--candidates" ./run_all.sh --no-deps --only pico      # + RP2350 size-feasible extras
# optimisation knobs; each tags the label, so the rows sit next to the default ones in results.csv
python3 pico/run_benchmarks.py --lib liboqs-r3 --match snova  # round 3 SNOVA (memory-optimised, liboqs main)
python3 pico/run_benchmarks.py --lib liboqs --keccak xkcp    # liboqs 0.16 with XKCP assembler Keccak
python3 pico/run_benchmarks.py --freq 133                    # the clock the RP2040 study used (default 200)
python3 pico/run_benchmarks.py --opt O2                      # sketch + core at -O2 (default -Os)
bash pico/tests/qemu_liboqs/run.sh             # no board: Keccak swap checked + instruction counts in QEMU
```

## 0.2  What each bench runs

| Stage (`--only`) | `--test` | What it measures | Code / library | Runs on | Output (`results/`) |
|---|---|---|---|---|---|
| `openssl` | pqc | keygen / sign / verify, operation only: mean, median, std, min, max, ops/s, cycles, sizes; EVP's per-call setup as extra `sign_setup` / `verify_setup` rows; `SIG_N` (100) runs for every algorithm | OpenSSL 3.5+ EVP; oqs-provider (liboqs) for Falcon | Mac, Pi | `openssl_sig_speed_<tag>.{csv,meta}` |
| `round3` | pqc, mqtt | Stage 1 as `openssl` and `liboqs` + Stage 2 as `mtls`, for the round 3 MAYO / SNOVA / MQOM / UOV sets (MQOM, UOV: Stage 1 only) | OpenSSL + oqs-provider `36cafae` on liboqs main `b196b57a`, and that liboqs directly; OpenSSL client | Mac, Pi | `{openssl,liboqs}_sig_speed_r3_<tag>.*`, `mqtt_mtls_*_<tag>_r3` |
| `liboqs` | pqc | same as `openssl`: the same C timing code, on liboqs directly | liboqs 0.16.0 (`liboqs_sig_speed` = `sig_speed.c` with `-DSIG_LIBOQS`) | Mac, Pi | `liboqs_sig_speed_<tag>.{csv,meta}` |
| `wolfssl` | pqc | signatures as `openssl` (the same C bench); the build is also the Stage 2 wolfSSL client | wolfSSL 5.9.4 (`wolfssl_sig_speed` = `sig_speed.c -DSIG_WOLFSSL`) | Mac, Pi | `wolfssl_sig_speed_<tag>.{csv,meta}` |
| `sdith` `faest` `hawk` `sqisign` `qruov` | pqc | SDitH, FAEST, QR-UOV: `SIG_N` runs, mean / median / std / min / max / p90 / p99 through `bench_template.c`. SQIsign: its own bench at `SIG_N`, mean only. HAWK: its own time-based bench, mean only | NIST submission reference C | Mac, Pi | `sig_summary_reference*.csv` |
| (end of every pqc run) | pqc | every signature above in the customer's Pico table | `to_customer_form.py` | — | `stage1_customer_form_<tag>.csv` |
| `tls` | mqtt | the key-exchange sweep: TLS 1.3 and mTLS handshake inside a full MQTT connection, every cert × 17 groups (`mqtt_bench.SWEEP_GROUPS`: ML-KEM-512/768/1024, the ML-KEM hybrids, X25519, P-256, HQC-1/3/5, FrodoKEM-640-AES), 200 connections each: mean / median / std / min / max / p90 / p99, handshakes/s; bytes up / down / total; socket writes / reads; TCP segments; on-wire estimate | `mqtt_tls_timer` (OpenSSL) against the broker machine's Mosquitto TLS / mTLS listeners; a failed combination is a row with its reason | two machines: `--serve-broker` + `--broker IP` | `tls_handshake_{pure,meta}_<tag>` |
| `kex` | mqtt | the KEM exchange as MQTT messages, for KEMs that can't (or can't only) run in TLS: Classic McEliece 348864 / 460896 / 6688128 / 6960119 / 8192128, HQC-1/3/5, ML-KEM-768 as the reference. Per exchange: key pair on the client, public key PUBLISHed, the broker's responder encapsulates and replies with ciphertext + SHA-256 of the secret + its encapsulation time, the client decapsulates and checks. keygen / encaps / decaps µs, broker round trip and exchange total ms (mean / median / std / min / max / p90), bytes up / down | `mqtt_kem_timer` (the timer's source built with liboqs 0.16: `KEM=` client, `KEM_RESPOND=1` responder started by `--serve-broker`), plain MQTT on :18830 | two machines: `--serve-broker` + `--broker IP` | `kem_exchange_{summary,raw,meta}_<tag>` |
| `mtls` | mqtt | Stage 2: TCP, handshake, MQTT CONNECT→CONNACK, total: mean / median / std / min / max; bytes up / down for the handshake, MQTT and the whole connect, and totals; socket writes / reads; TCP segments; on-wire estimate; cert sizes; failures as rows | Mosquitto + `mqtt_tls_timer` on OpenSSL or wolfSSL; X25519MLKEM768 | two machines: `--serve-broker` + `--broker IP` | `mqtt_mtls_{summary,raw,meta}_<tag>` |
| `pipeline` | pipeline | the only LoRaWAN / AES / Ascon measurement: per message, uplink and downlink frames: seal, open, broker round trip, end-to-end, each mean / median / std / min / max (+ p90), bytes per message; plus the Stage 2 columns | as `mtls` + `app_aead.c` (LoRaWAN 1.0.x / 1.1, AES-GCM, Ascon) | two machines, as `mtls` | `pipeline_{summary,msgs_raw,meta}_<tag>` |
| `pico` | pqc, mqtt | keygen / sign / verify, peak stack, flash / RAM; Pico W only (`mqtt_tls_bench`, needs `--broker` and `WIFI_SSID` / `WIFI_PASS`): the `mtls` and `pipeline` columns over Wi-Fi (6 payload schemes × up / down; no TCP segment counts) + wolfSSL's peak heap and peak stack | see the Pico table in §4; wolfSSL 5.9.4 TLS 1.3 client, X25519MLKEM768, ECDSA-P256 / ML-DSA-44 / Falcon-512 certs; `lora_aead.h` (BearSSL, ascon-c) | Pico W, Pico 2 W | `pico/logs/`, `results/*_pico_<board>.*` |
| (every run) | — | OS, board, compiler, library versions, ascon-c commit | `provenance.py` | — | `versions_<tag>.json` |

**Algorithms and their characteristics.** Sizes in bytes, from `results/sig_meta_*.csv`. "Where" says
which benches run it.

| Algorithm | Type (hard problem) | Status | Sets | Public key | Signature | Where |
|---|---|---|---|---|---|---|
| RSA-2048 / 3072 | integer factoring (classical) | baseline | 2 | 256 / 384 | 256 / 384 | all, TLS |
| ECDSA P-256 / 384 / 521 | elliptic curve (classical) | baseline | 3 | 64–132 | 64–132 | all, TLS |
| Ed25519 / Ed448 | elliptic curve (classical) | baseline | 2 | 32 / 57 | 64 / 114 | all, TLS |
| ML-DSA-44 / 65 / 87 | module lattice | FIPS 204 | 3 | 1312 / 1952 / 2592 | 2420 / 3309 / 4627 | all, TLS, pipeline |
| Falcon-512 / 1024 | NTRU lattice | FIPS 206 draft | 2 (+padded) | 897 / 1793 | ≤ 752 / ≤ 1462 | all, TLS (OpenSSL; wolfSSL since [finding 51](docs/findings.md)), pipeline |
| SLH-DSA SHA2 / SHAKE 128–256 s / f | hash-based | FIPS 205 | 12 | 32 / 48 / 64 | 7856 – 49856 | Stage 1 + Pico only (TLS refuses it) |
| MAYO-1 / 2 / 3 / 5 | multivariate | round 3 [33] | 4 | 1456 – 5554 | 239 – 964 | `round3`: Stage 1 (OpenSSL, liboqs), TLS; Pico (liboqs main; MAYO-3/5 too big) |
| SNOVA I / III / V × K / B / S | multivariate | round 3 [32] | 9 | 376 – 2716 | 272 – 896 | `round3`: Stage 1, TLS; Pico (liboqs main, memory-optimised) |
| MQOM v3, cat 1 / 3 / 5, GF(16) fast / short, GF(2) shorter, constant time | MPC-in-the-head | round 3 [34] | 9 (of 18) | 52 – 128 | 2492 – 13540 | `round3`: Stage 1 (OpenSSL: the 3 GF(16) fast sets); Pico (cat 1, memory-optimised) |
| UOV Is / Ip / III / V (+ pkc, pkc-skc) | multivariate | round 3 | 12 | 46591 – 3.2 M | 96 – 275 | `round3`: Stage 1 (liboqs); Pico: pkc on RP2350 (liboqs main), Ip classic (round 2 code, baked keys) |
| HAWK-512 / 1024 | lattice | withdrawn (2026) | 2 | 1024 / 2440 | 555 / 1221 | Stage 1 (reference), Pico |
| SDitH, FAEST | MPC-in-the-head / VOLE-in-the-head | round 3; the code here is older (SDitH 2023 threshold variant, FAEST 2.0) | many | 32 – 244 | 3540 – 45676 | Stage 1 (reference), Pico |
| QR-UOV, SQIsign | multivariate / isogeny | round 3; the code here is round 2 | many | 12266 – 173676 / 65 – 129 | 148 – 662 | Stage 1 (reference), Pico (QR-UOV) |

Round 3 of NIST's additional signatures (May 2026) kept FAEST, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV and
HAWK, and the HAWK team has since withdrawn it. Bracketed numbers are the [sources in docs/findings.md](docs/findings.md#sources);
the FIPS standards are [10–12].

| Key exchange / payload | What it is | Key | Per-message overhead | Where |
|---|---|---|---|---|
| ML-KEM-512 / 768 / 1024 | lattice KEM, FIPS 203 (pk 800 / 1184 / 1568 B) | — | — | TLS sweep (two machines) |
| X25519 | classical elliptic-curve key exchange (the pre-PQ reference) | — | — | TLS sweep (two machines) |
| X25519MLKEM768 | hybrid (classical + PQ), fixed for Stage 2 | — | — | TLS sweep, mtls, pipeline, Pico W (all two machines) |
| HQC-128 / 192 / 256 | code-based KEM (NIST's 2025 backup to ML-KEM) | — | — | not measured since the telemetry stage was retired |
| LoRaWAN 1.0.x (per message identical in 1.0.3 and 1.0.4) | AES-128-CTR encryption + AES-128-CMAC over B0 ‖ frame, 4-byte MIC | 2 × 128 bit session keys | 13 B (9 header + 4 MIC) | pipeline (host + Pico W) |
| LoRaWAN 1.1 | same encryption; uplink MIC = 2 bytes of each of two CMACs (two network keys), downlink MIC = 4 bytes of one (SNwkSIntKey) | 3 × 128 bit (+ NwkSEncKey for MAC commands) | 13 B | pipeline (host + Pico W) |
| AES-128-GCM / AES-256-GCM | AEAD, header as associated data, 16-byte tag | 128 / 256 bit | 25 B | pipeline (host + Pico W) |
| Ascon-AEAD128 | lightweight AEAD, NIST SP 800-232 | 128 bit | 25 B | pipeline (host + Pico W) |

## 0.3  The full pipeline and the LoRaWAN comparison

```text
client (mqtt_tls_timer)                          Mosquitto                        subscriber (same client)
 TLS 1.3 / mTLS, X25519MLKEM768, PQ certs ──────►  per-cert listener
 seal(frame) ─ PUBLISH pqc/pipe/<pid> ─────────►  routes  ─────────────────────────►  open + verify
 timed: seal µs · round trip through the broker · open µs · bytes each way, per message
```

`--modes plain,tls,mtls` gives the three transports, and `--aeads` gives the payload schemes, `none`
included as the reference. Every payload scheme protects the same LoRaWAN data frame, so the numbers
compare like for like. Each scheme runs as uplink frames (MHDR 0x40) and as downlink frames (MHDR 0x60,
Dir = 1), on the host and on the Pico W (`lora_aead.h`, the same bytes):

```text
MHDR(1) | DevAddr(4) | FCtrl(1) | FCnt(2) | FPort(1) | FRMPayload | MIC (4) or tag (16)
```

* **LoRaWAN 1.0.x** (1.0.0 to 1.0.4 compute data frames identically; 1.0.3 and 1.0.4 differ only in the
  join, which is not measured): FRMPayload is encrypted with AES-128 in CTR form (the spec's A_i blocks, from
  DevAddr and FCnt), and the MIC is the first 4 bytes of AES-CMAC over B0 ‖ frame.
* **LoRaWAN 1.1**: the same encryption. The uplink MIC is 2 bytes of the CMAC under SNwkSIntKey followed
  by 2 bytes of the CMAC under FNwkSIntKey, so there are two CMACs per uplink. A downlink carries 4 bytes of
  one CMAC, under SNwkSIntKey.
* **Downlinks** set Dir = 1 in A_i and B0. Their FCnt is the downlink counter, so an uplink and a downlink
  with the same counter value still get different keystreams.
* **AES-GCM and Ascon** take the 9-byte header as associated data, use a nonce built from DevAddr, FCnt
  and the direction, and add a 16-byte tag.

The version differences are in [docs/how_it_works.md §3.2](docs/how_it_works.md#32-what-each-lorawan-version-includes).

The code is checked against a published LoRaWAN 1.0 uplink (`40F17DBE49…2B11FF0D`), ChirpStack's LoRaWAN
1.1 downlink MIC, and the RFC 4493 CMAC examples; the host pipeline and the Pico run these checks before
sending, and refuse to send if one fails. The Pico's BearSSL / ascon-c version produces the same frames as the
host's OpenSSL / ascon-c version, byte for byte, for every scheme in both directions
(`pico/tests/aead_host_test`, 48 frames).

---

## 1.  Installation

### 1.1  Python

Python 3.12 or newer (pinned: 3.14.7 on the Mac; the Pi uses Pi OS Trixie's 3.13). The exact package
versions are in `requirements.txt`. On the Mac the venv is `.venv.nosync` (iCloud Drive skips `*.nosync`),
with `.venv` linking to it (§0).

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate                  # macOS / Linux
# .venv\Scripts\activate                   # Windows PowerShell
pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` holds only pyserial (the Pico runner): Python drives the benches, C does the timing.

```bash
python3 -c "import serial; print('ok')"
```

### 1.2  MQTT broker (Mosquitto)

The benches start their own Mosquitto processes (on the broker machine, `./run_all.sh --serve-broker`); they
only need the binary installed. Pick one:

```bash
# macOS
brew install mosquitto
mosquitto                                  # foreground
brew services start mosquitto              # background

# Linux (Ubuntu / Debian)
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl start mosquitto
sudo systemctl enable mosquitto

# Windows
# Download from https://mosquitto.org/download/ → Install Service + Install Broker
mosquitto                                  # from cmd / PowerShell

# Docker (any OS)
docker run -it --rm -p 1883:1883 eclipse-mosquitto:2 \
    mosquitto -c /mosquitto-no-auth.conf
```

Verify:

```bash
mosquitto_sub -h localhost -t test/topic   # terminal A
mosquitto_pub -h localhost -t test/topic -m "hello"   # terminal B → A prints "hello"
```

### 1.3  OpenSSL 3.5+ with ML-KEM / ML-DSA

Required by the `openssl`, `tls`, `mtls` and `pipeline` stages and by `gen_certs.sh`.

OpenSSL 3.5 (April 2025) ships ML-KEM and ML-DSA natively. Earlier releases need
the **oqs-provider** plugin.

#### macOS

```bash
brew install openssl@3                     # installs 3.5+
brew info openssl@3 | head -3              # confirm version

# macOS keeps Apple's old LibreSSL at /usr/bin/openssl. Add brew openssl to PATH:
echo 'export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Optional — the TLS scripts also probe /opt/openssl/bin/openssl as a fallback:
sudo ln -s /opt/homebrew/opt/openssl@3 /opt/openssl
```

#### Linux

```bash
# Ubuntu 24.10+ ships OpenSSL 3.4 in apt. For 3.5+ build from source:
sudo apt install -y build-essential perl
curl -LO https://www.openssl.org/source/openssl-3.5.0.tar.gz
tar xf openssl-3.5.0.tar.gz && cd openssl-3.5.0
./Configure --prefix=/opt/openssl
make -j$(nproc) && sudo make install_sw
echo 'export PATH=/opt/openssl/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

#### Windows

Use WSL2 with Ubuntu and follow the Linux steps, or download a pre-built
OpenSSL 3.5 from https://slproweb.com/products/Win32OpenSSL.html and add its
`bin` directory to `PATH`.

#### Verify

```bash
openssl version                            # → OpenSSL 3.5.x ...
openssl list -kem-algorithms | grep -i ml-kem
# → MLKEM512, MLKEM768, MLKEM1024
openssl list -signature-algorithms | grep -i ml-dsa
# → ML-DSA-44, ML-DSA-65, ML-DSA-87
```

### 1.4  wolfSSL with PQ support (the `wolfssl` stage builds it; by hand below)

wolfSSL is the embedded-class TLS library used in real IoT devices. `run_all.sh` builds it with
`network/build_wolfssl.sh` (Stage 1 bench, and the wolfSSL MQTT client of Stage 2 and the pipeline).

#### macOS

```bash
# Easiest path — Homebrew with the HEAD tap that includes ML-KEM / ML-DSA:
brew install wolfssl --HEAD

# If brew's wolfssl doesn't include PQ, build from source:
git clone https://github.com/wolfSSL/wolfssl.git && cd wolfssl
./autogen.sh
./configure \
    --enable-tls13 \
    --enable-experimental \
    --enable-kyber \
    --enable-dilithium \
    --enable-examples
make -j$(sysctl -n hw.ncpu)
sudo make install

# Verify the example binaries are runnable:
which wolfssl-server wolfssl-client    # or: ls ./examples/{server,client}/
```

#### Linux

```bash
sudo apt install -y autoconf automake libtool make
git clone https://github.com/wolfSSL/wolfssl.git && cd wolfssl
./autogen.sh
./configure --enable-tls13 --enable-experimental --enable-kyber --enable-dilithium --enable-examples
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### Verify

```bash
wolfssl-server -? 2>&1 | head -3
# Should print something like "server [...] -p port -v version ..."
```

### 1.5  liboqs (the `liboqs` stage)

`./run_all.sh --only liboqs` builds liboqs 0.16.0 once into `~/.cache/iot-pqc/liboqs-host`. It then times it
with `signatures/liboqs_sig_speed`, which is `sig_speed.c` compiled with `-DSIG_LIBOQS`. So liboqs
and OpenSSL are timed by the same C code: the same 64-byte message, loops, statistics and cycle counter.

```bash
LQ=~/.cache/iot-pqc/liboqs-host
cc -O2 -DSIG_LIBOQS signatures/sig_speed.c -o signatures/liboqs_sig_speed \
   -I$LQ/include -L$LQ/lib -Wl,-rpath,$LQ/lib -loqs -lm
signatures/liboqs_sig_speed 200 ML-DSA-44 Falcon-512 SLH_DSA_PURE_SHA2_128F 2> sizes.meta
```

### 1.6  NIST reference-implementation benchmarks (optional, for `signatures/reference/`)

For the NIST additional signatures that are **not** in liboqs (HAWK, SDitH, QR-UOV,
FAEST, SQIsign), `signatures/reference/` compiles each
algorithm's own NIST submission C reference against a generic timing harness
(`bench_template.c`) and aggregates the output into
`results/sig_summary_reference.csv`, which the Stage 1 table reads next to the OpenSSL and liboqs rows.

```bash
cd signatures/reference

# 1. Download submission packages (script tries canonical URLs)
./clone_algos.sh

# 2. Build + probe (1-iter run per variant to capture pk/sig/sk sizes)
python run_reference_benchmarks.py --probe-only

# 3. Real benchmarks (--iterations, default 200; run_all.sh passes SIG_N)
python run_reference_benchmarks.py --algos SDitH FAEST QR-UOV
```

Full workflow + per-algorithm gotchas in `signatures/reference/README.md`.

`bench_template.c` now also times **keygen** (emits `<algo> keygen` rows), so the
`generic-bench` algos that compile against it (e.g. **SDitH**) pick up keygen
latency automatically on the next run — re-run step 3 above. The `native-bench`
algos (**HAWK, SQIsign**) use their own upstream benchmark binaries;
**HAWK** keygen is captured too because `parse_native_output.py` reads the
`kg(ms)` column. These native rows carry the mean only.

---

## 3.  Certificates and the TLS key-exchange sweep (OpenSSL 3.5+)

Every TLS / mTLS measurement is an MQTT connection through the broker on another machine; this section covers
the certificates both machines share and the key-exchange sweep.

### 3.1  Generate certificates

The TLS scripts expect `./certs/<sig>/{CA.crt, server.crt, server.key}` —
one folder per signature algorithm. Use the committed `gen_certs.sh` in the
repo root:

```bash
chmod +x gen_certs.sh
# use a real OpenSSL 3.5 (NOT Apple's /usr/bin/openssl = LibreSSL):
OSSL=/opt/homebrew/opt/openssl@3/bin/openssl ./scripts/gen_certs.sh
ls certs/   # MLDSA44/ … FALCON512/ … RSA3072/ ECDSAP256/ ED25519/ … round3/ (MAYO1/ … SNOVA1K/ …, the round3 stage's)
```

`gen_certs.sh` auto-detects/loads oqs-provider and generates a CA + SAN server
cert per algorithm. Coverage:

| Family | Algorithms | Provider | Usable as TLS cert? |
|---|---|---|---|
| ML-DSA | MLDSA44 / 65 / 87 | native (3.5+) | **yes** |
| Falcon | FALCON512 / 1024 | oqs-provider | **yes** |
| MAYO, SNOVA (round 3) | MAYO1 / 2 / 3 / 5, SNOVA1K … SNOVA5S, in `certs/round3/` | oqs-provider `36cafae` (the `round3` stage) | **yes** |
| RSA | RSA3072 | native | yes (classical baseline) |
| ECDSA | ECDSAP256 (P-256) | native | yes (classical baseline) |
| EdDSA | ED25519 | native | yes (classical baseline) |
| SLH-DSA | SLHDSA128F / 128S / 192F | native (3.5+) | **NO** — cert generates, but the OpenSSL 3.5 TLS layer rejects it (`ssl_set_cert: unknown certificate type`). Stays in the signature benchmarks only. |

So the four "classical + lattice" cert types **RSA, ECDSA, EdDSA, ML-DSA** are all
wired in, plus Falcon (and round 3 MAYO / SNOVA) via oqs-provider. Excluded from TLS: **SLH-DSA**
(OpenSSL TLS limitation above), **UOV** (public keys 412 KB–3.2 MB, too large for a
cert), **MQOM** (Stage 1 only: no MQOM certificates are made), and **HAWK / SQIsign / FAEST**
(reference-only, not in oqs-provider).

**oqs-provider is required for Falcon/MAYO/SNOVA** and is **not** in Homebrew —
build it from source (liboqs + oqs-provider against your brew OpenSSL 3.5), then
either copy `oqsprovider.dylib` into `$(brew --prefix openssl@3)/lib/ossl-modules/`
or export `OPENSSL_MODULES=<dir with oqsprovider.dylib>`. `gen_certs.sh`,
`tls_sweep.sh` auto-detects it. Verify with
`openssl list -signature-algorithms | grep -iE 'falcon|mayo|snova'`; if a name
differs, edit the `OQS_SIGS` list at the top of `gen_certs.sh`.

### 3.2  The key-exchange sweep through the broker — `tls_sweep.sh`

Every cert set × group × {TLS, mTLS}, as full MQTT connections to the broker machine
(`./run_all.sh --serve-broker` there; this machine needs the same `certs/`) →
`results/tls_handshake_pure.csv` + `tls_handshake_meta.json`:
```bash
bash network/build_timer.sh openssl
HOST=<broker IP> ITERS=200 bash network/tls_sweep.sh     # or: ./run_all.sh --broker <IP> --only tls
```
The sweep connects to the broker's per-certificate listeners: TLS on 18830+101+i, mTLS on 18830+1+i, the
Stage 2 ports. Those listeners accept every group in `mqtt_bench.SWEEP_GROUPS` (17: pure ML-KEM, the
IETF and oqs-provider ML-KEM hybrids, X25519 / P-256, HQC-1/3/5, FrodoKEM-640-AES), and the client offers only the
one being measured. Stage 2 and the pipeline keep the customer's X25519MLKEM768. The Pico W runs the same sweep
for the 13 groups its wolfSSL has ([finding 78](docs/findings.md)).
It loads oqs-provider for Falcon / MAYO / SNOVA. Each row has the handshake's time stats, bytes up / down,
socket writes / reads, TCP segments, the on-wire estimate (§0.2) and a status; a failed combination keeps its
reason.

> **bash gotcha:** do not name a shell variable `GROUPS` — it is reserved (the
> user's group IDs; `=20`/`staff` on macOS), so assignments are silently ignored.
> The sweep uses `KEMGROUPS`.

### 3.5  `openssl speed`-style signature timing — `sig_speed.c`

`openssl speed` cannot benchmark PQC signatures (no ML-DSA/SLH-DSA, no
oqs-provider sigs, and no keygen even for classical). `signatures/sig_speed.c`
is the EVP-based equivalent — keygen/sign/verify for any signature OpenSSL or
oqs-provider exposes:

```bash
cd signatures
cc -O2 sig_speed.c -o openssl_sig_speed \
   -I"$(brew --prefix openssl@3)/include" -L"$(brew --prefix openssl@3)/lib" -lcrypto -lm
./openssl_sig_speed 100 ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128f falcon512 \
    > ../results/openssl_sig_speed_manual.csv 2> ../results/openssl_sig_speed_manual.meta
```
The same file builds for liboqs (`-DSIG_LIBOQS`) and wolfSSL (`-DSIG_WOLFSSL`): see its header.
For the classical RSA/ECDSA sign-verify baseline, the real `openssl speed` works:
`openssl speed -seconds 3 rsa3072 ecdsap256 ed25519`.

`signatures/reference/collect_reference_sizes.py` populates pk/sk/sig
sizes for the reference-set algos (HAWK/FAEST/SQIsign from `api.h`) into `results/sig_meta_reference.csv`, so the workbook's size
columns fill: run it before the Stage 1 table (`run_all.sh` does not call it).

---

## 4.  Project plan (Topic C) on the Pi — Stage 1, Stage 2, AES vs Ascon, wolfSSL

`./run_all.sh` (§0) runs everything below and writes into `results/` with a `_$TAG` suffix
(default `mac` / `pi`; use `TAG=pi4` / `TAG=pi5` per board):

```bash
./run_all.sh --only openssl,wolfssl,liboqs                  # Stage 1 signatures: the only local stages
./run_all.sh --broker <broker-ip> --only mtls,pipeline,tls   # MQTT stages: broker on another machine (§0.1)
# customer's custom builds instead of the system ones:
OPENSSL_PREFIX=/opt/openssl-3.5 MOSQUITTO=/opt/mosquitto-oqs/sbin/mosquitto ./run_all.sh --only openssl,mtls --broker <broker-ip>
```

PQ TLS needs OpenSSL ≥ 3.5 (Raspberry Pi OS Trixie ships it; on Bookworm use
`OPENSSL_PREFIX`). Falcon (and round 3 MAYO / SNOVA) inside OpenSSL need oqs-provider (§3.1);
the runner picks up `oqs-provider/_build/lib` or `oqs-provider/build/lib`.

**Which library runs which algorithm**

| Bench | Signatures | KEM / key exchange | AEAD |
|---|---|---|---|
| Stage 1 `openssl` (`sig_speed.c`) | OpenSSL 3.5 EVP: RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA; oqs-provider (liboqs): Falcon | — | — |
| Stage 1 `round3` (`sig_speed.c`, both builds) | oqs-provider `36cafae`: round 3 MAYO, SNOVA, MQOM; liboqs main directly: those and round 3 UOV | — | — |
| Stage 1 `wolfssl` (`wolfssl_sig_speed`, C) | wolfSSL 5.9.4 native: RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA, Falcon (experimental, double precision) | — | — |
| Stage 1 reference | NIST submission C (HAWK, SDitH, QR-UOV, FAEST, SQIsign) | — | — |
| Stage 1 `liboqs` (`liboqs_sig_speed`, C) | liboqs 0.16.0 built in `~/.cache/iot-pqc` (same release as the Pico build): ML-DSA, Falcon, SLH-DSA | — | — |
| `tls` sweep (`tls_sweep.sh`) | as `mtls` (OpenSSL client) | 17 groups (`SWEEP_GROUPS`): ML-KEM-512 / 768 / 1024; X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 and oqs-provider's 5 ML-KEM hybrids; X25519, P-256; HQC-1 / 3 / 5, FrodoKEM-640-AES. The Pico W: the 13 wolfSSL has | TLS 1.3 suite |
| Stage 2 `mtls` (plain / TLS / mTLS) | certs made by `openssl` (+oqs-provider); client = OpenSSL or wolfSSL; broker = Mosquitto on system OpenSSL | X25519MLKEM768 (fixed) | TLS 1.3 suite |
| `pipeline` (host, and the Pico W's `mqtt_tls_bench`) | as `mtls` | X25519MLKEM768 (fixed) | TLS 1.3 suite outside; inside, per message, uplink and downlink frames: LoRaWAN 1.0.x / 1.1, AES-GCM (OpenSSL; BearSSL on the Pico), Ascon (ascon-c), none |

**Outputs**

| File | What |
|---|---|
| `stage1_customer_form_$TAG.csv` | Every signature in the Pico `results.csv` columns (+ `Library`): sizes, keygen/sign/verify mean/median/std/cycles/ops_s, `status`. Stacks with the Pico rows in one sheet. wolfCrypt rows carry mean + ops/s only (its benchmark prints no per-op spread). |
| `openssl_sig_speed_$TAG.{csv,meta}` | Raw Stage 1 OpenSSL output; `.meta` holds sizes and `UNSUPPORTED` / `VERIFY_FAIL` lines. |
| `tls_handshake_pure_$TAG.csv`, `tls_handshake_meta_$TAG.json` | The key-exchange sweep through the broker, per (mode × cert × group): handshake n, mean, median, p90/p99, min, max, bytes, socket calls, TCP segments, status. |
| `mqtt_mtls_summary_$TAG.csv` | Stage 2 per (client library × signature): `status`, cert sizes, handshake bytes tx/rx, TCP / mTLS / MQTT CONNECT→CONNACK mean/median/std; plus the plain-MQTT reference row. |
| `mqtt_mtls_raw_$TAG.csv`, `mqtt_mtls_meta_$TAG.json` | Per-connection samples; versions + run settings. |
| `pipeline_summary_$TAG.csv` | The Stage 2 columns plus `AEAD`, `Direction` (uplink / downlink), `TLS_suite`, `msgs`, `seal_mean_us`, `open_mean_us`, `rtt_median_ms`, `e2e_{median,p90,mean}_ms`, `msg_tx_B` / `msg_rx_B`, per (library × signature × mode × payload scheme). |
| `pipeline_msgs_raw_$TAG.csv`, `pipeline_meta_$TAG.json` | Per-message seal / round-trip / open µs and bytes; versions + settings. |
| `versions_$TAG.json` | OS, kernel, Pi model, firmware (`vcgencmd`), compiler, OpenSSL, oqs-provider with the liboqs built into it (`oqsprovider`), the installed liboqs (`liboqs_system`), the liboqs 0.16 build that the liboqs stage and the Pico use (`liboqs_bench`), Mosquitto, wolfSSL, ascon-c commit, Python packages, and the OpenSSL bundled inside `cryptography`. |

Stage 2 broker: `mqtt_bench.py` starts one Mosquitto per signature, with mTLS on port
`base+1+i`, server-auth TLS on `base+101+i` and plain MQTT on `base` (default 18830). `run_all.sh`
runs it only against `--serve-broker` on another machine (§0.1). The mTLS listener has `require_certificate true` and `use_identity_as_username true`,
all listeners use TLS 1.3, and their OpenSSL config accepts X25519MLKEM768 (the customer's broker setting,
and the only group every Stage 2 client offers) plus the `tls` sweep's 16 other groups (`?`-optional: skipped where this OpenSSL lacks them). A cert the broker or client library can't
handle becomes a row with the reason in `status`. To put the broker on the Pi 5 and the
client elsewhere, run `--role broker` on the Pi 5 and `--role client --host <pi5>` on the
client, with the same `certs/`.

Findings from these benches are in [docs/findings.md](docs/findings.md).

**Constrained hardware (Pico W = RP2040 Cortex-M0+, Pico 2 W = RP2350 Cortex-M33): which code runs there**

| Pico sketches | Implementation | Tuned for Cortex-M? |
|---|---|---|
| ML-DSA-44/65/87 (`mldsa_bench`) | mldsa-native `ref` (the code liboqs ships) | No: portable C, large stack arrays |
| Falcon, SLH-DSA (12 sets) (`falcon_bench`, `slhdsa_bench`) | PQClean `clean` | No: portable reference C |
| HAWK, SDitH, QR-UOV, FAEST, UOV-Ip | NIST submission reference code | No |
| RSA, ECDSA | BearSSL (bundled in arduino-pico) | Partly: constant-time C written for 32-bit MCUs |
| Ed25519 / Ed448 | rweather Crypto / OpenSSL Goldilocks port | Portable C |
| **wolfssl_bench** (new) | wolfSSL 5.9.4: small-mem ML-DSA/SLH-DSA, Cortex-M assembly for ECDSA/RSA (`sp_armthumb.c` M0+, `sp_cortexm.c` M33) | Yes: library built for MCUs; SHA-3/AES still C on Arduino (its Thumb-2 asm isn't in the Arduino package) |
| **mqtt_tls_bench** pipeline (`lora_aead.h`) | LoRaWAN 1.0.x / 1.1 (BearSSL AES-128-CTR + CMAC built on `aes_ct`), BearSSL AES-GCM (`aes_ct`), ascon-c `armv6m_lowsize` (hand-written M0 assembly); known-answer tests run on the board first; frames go through the broker | Yes for Ascon; AES is software on both chips (no AES engine) |
| **liboqs_bench** | liboqs bare-metal (`OQS_EMBEDDED_BUILD`), cross-compiled per CPU by `make_liboqs_lib.sh`: 0.16 for ML-DSA, Falcon, SLH-DSA; liboqs main (`LIBOQS_ROUND=3`, `OQS_MEMOPT_BUILD`) for round 3 MAYO-1/2, SNOVA (9 sets), MQOM v3 cat 1, UOV pkc (RP2350) | By default no: portable C, but the same code as the Pi/Mac liboqs stage; reports peak stack per op. With `--keccak xkcp`, its Keccak is XKCP's ARMv6-M / ARMv7-M assembler (docs/how_it_works.md part 4) |

So the existing Pico numbers are an upper bound on cost: reference C with no Cortex-M
tuning, as a 2026 RP2040 study also frames its PQClean numbers
([arXiv:2603.19340](https://arxiv.org/html/2603.19340v5): ML-DSA-44 sign 158.9 ms,
verify 44.0 ms, 50.6 KB peak signing stack at 133 MHz). wolfSSL is the maintained,
MCU-targeted alternative with the same schemes. Others checked and not used:
[pqm4](https://github.com/mupq/pqm4) is Cortex-M4 assembly with no RP2350 port and is being
archived; Mbed TLS / TF-PSA-Crypto has ML-DSA-87 only ([roadmap](https://mbed-tls.readthedocs.io/en/latest/project/roadmap/),
ML-KEM later); liboqs can build bare-metal (`OQS_EMBEDDED_BUILD`, you supply the RNG) but
ships no Pico port - so `liboqs_bench` adds one. TF-PSA-Crypto 1.2 (Mbed TLS) does ship ML-DSA, but as a
wrapper around mldsa-native, ML-DSA-87 only; `mldsa_bench` (ML-DSA-87) already runs that code directly.

**Plan requirements → where they are covered**

| Req | Covered by |
|---|---|
| R1 MQTT over mTLS with PQ certs on a Pi/VM | `mqtt_bench.py` + `gen_certs.sh` (server + client certs per algorithm) |
| R2 / R3 / R4 / R8 LoRaWAN split, setup, ChirpStack, shared architecture | Not benchmark code: team/infrastructure work on the test bench |
| R5 all algorithms, customer's form | `stage1_customer_form_$TAG.csv` (Pico columns); Stage 2 sweeps every cert type |
| R6 AES and Ascon | `pipeline_summary_$TAG.csv` and `pipeline_summary_pico_<board>.csv`: real LoRaWAN 1.0.x / 1.1 vs AES-GCM vs Ascon on the same frame, uplink and downlink, end to end through the broker (host and Pico W) |
| R7 versions | `versions_$TAG.json` and every `*_meta_$TAG.json`, plus a `Library` column per row |
| §4.1 plain MQTT reference | plain row in `mqtt_mtls_summary_$TAG.csv`; `plain` × `none` rows in `pipeline_summary_$TAG.csv` |
| §4.2 sizes, sign/verify, handshake bytes each way, mTLS + MQTT connect time, failures as results | Stage 1 table + `mqtt_mtls_summary_$TAG.csv` (`status`). Peak stack and firmware size are Pico-only metrics (`pico/`). |
| R9 progress meetings | Not code; the CSVs above are the material for the 2 Oct 2026 meeting |

---

## 5.  Troubleshooting

| Symptom | Fix |
|---|---|
| Pico: `flash ... failed (write failed: [Errno 1] Operation not permitted: '/Volumes/RPI-RP2/...')` | macOS privacy blocks the terminal app from removable drives. The runner now falls back to `picotool load -x` over USB by itself. To allow the drive too: System Settings → Privacy & Security → Files and Folders → your terminal app → Removable Volumes, then reopen the terminal. |
| `tls handshake failed: self-signed certificate in certificate chain` (every TLS row) | This machine's `certs/` is not the broker's (a different CA). On the broker machine, from the repo root: `rsync -a --delete certs/ <user>@<client>:<repo>/certs/`. `run_all.sh --broker` now checks this first and skips the TLS stages. |
| `cannot load client key: ...: Permission denied` or `key values mismatch` (every mTLS row) | The keys are unreadable (made with `sudo`: `sudo chown -R $USER certs`) or from another certificate set (rsync as above). |
| `Error setting groups: X25519MLKEM768` | OpenSSL is < 3.5. Re-install with `brew install openssl@3` and fix `PATH`. |
| `unable to find KEM "MLKEM512"` | OpenSSL 3.0–3.4 without oqs-provider. Upgrade to 3.5+ or install oqs-provider. |
| `verify error: unable to get local issuer certificate` | Pass `-CAfile certs/<sig>/CA.crt` on the client. |
| `source: no such file or directory: .venv/bin/activate` | No venv in the current folder yet — `python3 -m venv .venv` first. |
| `bash: ./scripts/gen_certs.sh: bad interpreter` | Windows line endings. `tr -d '\r' < gen_certs.sh > tmp && mv tmp gen_certs.sh`. |
