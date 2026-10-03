# How the benches work, and how to test them

Four parts:

1. **Test plan per device.** What to run on the MacBook, the Pi 4, the Pi 5 and the Pico boards, in
   what order, and what to check. Starts with a dry run on the Mac.
2. **Stage by stage.** Which program runs, which library it calls, which functions it calls in which
   order, and exactly what the timer covers.
3. **LoRaWAN, AES, Ascon, GCM and CMAC.** What each one is, what each LoRaWAN version includes, and
   how our AES-GCM and Ascon rows relate to LoRaWAN.
4. **Optimising the Pico code.** What was changed, how it was checked without a board, what it gained,
   and what is left.

Numbers in square brackets, like [4], are the numbered [sources in the README](../README.md#sources).

Versions in this document are the ones pinned on 28 Sep 2026. Every run records its
own versions in `results/versions_<tag>.json` (plan R7), so quote versions from that file, not from
here.

| Component | Version (pinned 28 Sep 2026) | Used by |
|---|---|---|
| macOS / CPU / compiler | macOS 26.6.2 (25G83), Apple M1 Pro, Apple clang 21.0.0 | the Mac host builds (`cc`) |
| Homebrew + build tools | Homebrew 7.0.6; cmake 4.4.3, autoconf 2.73, automake 1.19, libtool 2.6.2 | liboqs, oqs-provider and wolfSSL builds |
| OpenSSL | 3.6.4 (Homebrew `openssl@3`) | Stage 1 `openssl`, `tls`, `mtls`, `pipeline`, cert generation, Mosquitto's TLS |
| oqs-provider | commit c174ed7 (0.12.0-dev, 12 Sep 2026), built against **liboqs 0.16.0** | Falcon inside OpenSSL (its round 2 MAYO / SNOVA sets are no longer run: round 3 replaced them) |
| round 3 pair | oqs-provider 36cafae (19 Sep 2026) on liboqs main b196b57a (`0.16.0-50`, 24 Sep 2026). 36cafae needs unreleased liboqs, so this pair sits **beside** the pinned one, in `~/.cache/iot-pqc/{liboqs-r3,oqs-provider-r3-build}` | the `round3` stage (round 3 MAYO / SNOVA / MQOM, and UOV through liboqs directly), the round 3 brokers of `--serve-broker`, and the Pico's round 3 library (`LIBOQS_ROUND=3`, same liboqs commit) |
| liboqs | **0.16.0** (tag, commit 5a1a854), one build in `~/.cache/iot-pqc/liboqs-host` (`OQS_USE_OPENSSL=OFF`) | Stage 1 `liboqs` (`liboqs_sig_speed`, C) and oqs-provider; the same release is cross-compiled for the Pico |
| wolfSSL | 5.9.4 (`v5.9.4-stable`; `build_wolfssl.sh`, `make_wolfssl_lib.sh`) | Stage 1 `wolfssl`, the wolfSSL client in `mtls` / `pipeline`, Pico `wolfssl_bench` |
| ascon-c | commit 446347f (`CRYPTO_VERSION` 1.3.0, NIST SP 800-232) | `pipeline` (host), the Pico W's pipeline (`mqtt_tls_bench`) |
| Mosquitto | 2.1.2, linked to Homebrew OpenSSL 3.6.4 | `mtls`, `pipeline` broker (on the broker machine) |
| Python | 3.14.7 (Homebrew), venv in `.venv.nosync` (linked as `.venv`) | every Python script |
| pyserial | 3.5 | the Pico runner's serial port |
| arduino-cli | 1.5.1 | Pico builds and flashing |
| arduino-pico core | `rp2040:rp2040` 6.1.1: pqt-gcc 5.0.0-9576866 (GCC 16.1.0), newlib 4.6.0, Pico SDK 2.3.0, BearSSL bundled | every Pico sketch; the host test of the Pico's pipeline crypto compiles the same BearSSL |
| rweather Crypto | 0.4.0 (Arduino library) | Pico Ed25519 sketch |
| XKCP | commit 4affab4 | the optional Pico Keccak (part 4) |
| QEMU | 11.1.1 | `pico/tests/qemu_liboqs` |
| Pi | recorded at run time in `versions_<tag>.json` (Pi OS Trixie: OpenSSL 3.5.x, Python 3.13) | the Pi runs |

The [Mac] results so far were measured before this pin: oqs-provider 8b87173 with liboqs 0.15.0,
wolfSSL 5.9.2, Python 3.9.6, cryptography 48.0.0, arduino-pico 5.6.0. The README's findings state this
per item.

---

## 1. Test plan per device

### 1.0 On every device, before anything else

The pipeline (`mqtt_tls_timer` with `MSGS > 0`, and the Pico W's `mqtt_tls_bench`) runs a self-test before
sending anything, against published test vectors:
- the LoRaWAN 1.0 uplink frame (from lora-packet);
- a LoRaWAN 1.1 downlink MIC (ChirpStack/brocaar);
- AES-CMAC (RFC 4493);
- Ascon (the ascon-c KAT, on the Pico);
- a round trip plus tamper rejection for every payload scheme, uplink and downlink, and that the two
  directions never produce the same ciphertext (host).

If it fails, the pipeline refuses to send (the Pico's pipeline blocks then carry the reason as their status).

Record each device's details in the lab notes; `versions_<tag>.json` captures the software side:
- board and model (`/proc/device-tree/model` on a Pi);
- whether the CPU has AES instructions (the `cpu_aes` field; the Pi 4 has none, the Pi 5 does);
- cooling, and whether the Pi is throttled (`vcgencmd get_throttled` should print `0x0`).

### 1.0a Dry run on the Mac (do this first)

1. Activate the venv, then run `./run_all.sh --dry-run`. It builds and measures nothing; it checks
   the prerequisites and prints the stages that would run:

   ```bash
   cd PQ_MQTT_mTLS_for_IoT_LoRa && source .venv/bin/activate
   ./run_all.sh --dry-run
   ```

   Every `[--]` line names its fix:
   - OpenSSL ≥ 3.5;
   - oqs-provider (optional), and whether its build matches its source;
   - the round 3 provider (built by the `round3` stage on first use);
   - with `--broker IP`: the broker is reachable, and `certs/` has its CA;
   - compiler and build tools;
   - Mosquitto;
   - Python packages;
   - certificates (made automatically);
   - arduino-cli, and a plugged-in Pico (optional).

2. Run `./run_all.sh --quick --no-deps`. It runs every stage with a few iterations, in about
   5–15 minutes, and writes `results/*_mac_quick.*`.
   - It skips the NIST reference builds; add `--lib reference` to include them.
   - A plugged-in Pico runs one sketch (ML-DSA-44).

   Look for a `[!]` line: each one names the stage that failed and why, and the run carries on. The
   quick numbers prove the chain works; they are not results to report.
3. Run `./run_all.sh --no-deps` for the real Mac numbers, or go straight to the Pi.

What the two flags are for:
- `--quick` exists to catch a broken prerequisite in 5 minutes rather than an hour into a real run.
  Use it first on each new machine; never report its numbers.
- `--no-deps` skips the brew / apt install step. That step installs only missing packages and never
  upgrades installed ones, so versions can't drift mid-study. Plain `brew install` would upgrade (see
  README finding 34). Use `--no-deps` once everything is installed.

Expected on a Mac that has run nothing yet:
- `gen_certs.sh` creates `certs/` (about a minute);
- `build_wolfssl.sh`, the liboqs build and the round 3 pair (liboqs main + oqs-provider 36cafae) take a
  few minutes, once each (they're cached in `~/.cache/iot-pqc`).

### 1.1 MacBook (development host, Apple M-series)

Purpose: make sure everything builds and runs before the Pis. Mac numbers are an upper bound; they
are not the IoT result.

| Step | Command | Check |
|---|---|---|
| 1 | `./run_all.sh --no-deps --only openssl` | `openssl_sig_speed_mac.meta` has no unexpected `UNSUPPORTED` lines. Cycle counts are 0 unless run with `sudo -E`. |
| 2 | `./run_all.sh --no-deps --only liboqs` | `liboqs_sig_speed_mac.meta` has a size line per algorithm and no unexpected `UNSUPPORTED`. |
| 3 | `./run_all.sh --no-deps --only wolfssl` | `wolfssl_sig_speed_mac.meta` has a size line per algorithm; Falcon rows are `PARTIAL` (no keygen). |
| 5 | on another machine `./run_all.sh --serve-broker`, here `./run_all.sh --no-deps --broker <its IP> --only tls` | `tls_handshake_pure_mac_remote.csv` has one row per mode × cert × group; failures carry their reason. |
| 5b | `ls certs/*/client.crt` | Stage 2 needs a client certificate per algorithm. `run_all.sh` runs `gen_certs.sh` only when *no* client certificate exists; after changing OpenSSL or oqs-provider, run `bash scripts/gen_certs.sh` yourself. |
| 6 | on another machine `./run_all.sh --serve-broker`, here `./run_all.sh --no-deps --broker <its IP> --only mtls` | `mqtt_mtls_summary_mac.csv`: status `OK` for classical, ML-DSA and Falcon with both clients. The expected failures (SLH-DSA) are rows with the reason. Round 3 MAYO / SNOVA: `--only round3` (OpenSSL client). |
| 7 | `./run_all.sh --no-deps --broker <its IP> --only pipeline` | `pipeline_summary_mac_remote.csv`: every plain/TLS/mTLS × payload-scheme × uplink/downlink row `OK`. `msg_tx_B` differs by exactly the scheme overhead. |
| 9 | `bash pico/tests/aead_host_test/run.sh` | "all Pico pipeline crypto checks pass on the host": the Pico's LoRaWAN / GCM / Ascon frames equal the host's, byte for byte. |

Steps 5–7 count only with the broker on another machine (the Pi, or the Mac serving the Pi): a client and
a broker on one machine measure no network, so `run_all.sh` skips the MQTT stages without `--broker`, and
`collate_results.py` leaves out any run whose broker was local. Files get a `_remote` suffix.

### 1.2 Raspberry Pi 4 (the constrained-Linux device; no AES instructions)

Purpose: the device-class numbers, and the machine where AES and Ascon may swap places.

```bash
TAG=pi4 ./run_all.sh                 # everything; about 3-4 h at SIG_N=100, mostly SLH-DSA "s" signing
```

Check, in addition to the Mac checks:

1. `versions_pi4.json` → `cpu_aes: false`. wolfSSL was built with `--enable-armasm=no-crypto`, so its
   AES is software, like the Pico's.
2. `pipeline_summary_pi4*.csv` (the Pi as client of a broker on another machine): compare Ascon with
   AES-128-GCM here. This is the comparison the plan asks for ("does Ascon or AES-256 cost more than
   LoRaWAN's AES-128?") on a CPU without AES hardware.
3. `stage1_customer_form_pi4.csv`: every algorithm has a row. A failure is a `status`, not a missing
   row.
4. A 32-bit Pi OS needs `ASCON_IMPL=opt32` in the environment.

### 1.3 Raspberry Pi 5 (broker host; has AES instructions)

1. Run the same full run with `TAG=pi5 ./run_all.sh`. `cpu_aes` should be true, and AES should
   return to being faster than Ascon.
2. Then run the two-host Stage 2 / pipeline: the broker on the Pi 5, the client on the Pi 4, over
   the real network. Through `run_all.sh` (every MQTT stage, round 3 included):

   ```bash
   # Pi 5 (or the Mac)
   ./run_all.sh --serve-broker            # prints the command for the client, with this machine's IP
   # the same certs/ on both: from the Mac, which reaches both Pis over SSH (README section 0.1)
   rsync -a --delete <pi5-user>@<pi5-ip>:PQ_MQTT_mTLS_for_IoT_LoRa/certs/ /tmp/certs/
   rsync -a --delete /tmp/certs/ <pi4-user>@<pi4-ip>:PQ_MQTT_mTLS_for_IoT_LoRa/certs/
   # Pi 4
   ./run_all.sh --broker <pi5-ip> --dry-run
   TAG=pi4_to_pi5 ./run_all.sh --broker <pi5-ip> --test mqtt,pipeline
   ```

   Or by hand, per stage:

   ```bash
   # Pi 5
   python3 network/mqtt_bench.py --role broker
   # Pi 4 (same certs/ copied over)
   python3 network/mqtt_bench.py --role client --host <pi5-ip> --tag pi4_to_pi5
   python3 network/mqtt_bench.py --role client --host <pi5-ip> --tag pi4_to_pi5 --messages 200
   ```

   Only these runs give meaningful `rtt_median_ms` / `e2e_*` numbers; on one machine the broker
   round trip is loopback noise.

### 1.4 Pico W (RP2040, Cortex-M0+, 264 KB RAM) and Pico 2 W (RP2350, Cortex-M33, 520 KB RAM)

Flashed from the Mac, one board at a time; the runner detects which board is plugged in.

```bash
python3 pico/run_benchmarks.py --list                 # what will run on this board
python3 pico/run_benchmarks.py --lib liboqs           # liboqs 0.16 on the MCU (same code as the host)
python3 pico/run_benchmarks.py --lib wolfssl          # wolfSSL 5.9.4 on the MCU
python3 pico/run_benchmarks.py                        # everything validated for this board
python3 pico/run_benchmarks.py --candidates           # RP2350 only: size-feasible, not yet validated
# Pico W / Pico 2 W over Wi-Fi: Stage 2 + the LoRaWAN / AES / Ascon pipeline, against ./run_all.sh --serve-broker
export WIFI_SSID="<ssid>"; read -rs WIFI_PASS; export WIFI_PASS
BROKER=<this Mac's LAN IP> python3 pico/run_benchmarks.py --test mqtt
```

Check:

1. The `mqtt_tls_bench` log has `#kat LoRaWAN / AES-CMAC / Ascon known-answer checks: OK` (the 1.0 uplink,
   the 1.1 downlink MIC, RFC 4493 CMAC, the Ascon KAT). With FAIL, the protected pipeline blocks don't send.
2. `verify OK: n/n` in every signature log. Anything less is a correctness failure, not a speed
   result.
3. `pico/logs/results.csv`: `RUNTIME_MEMORY_FAIL` / `STACK_OVERFLOW` rows are results the plan
   wants reported, not errors to hide.
4. Watch the first hardware runs of `wolfssl_bench`, `liboqs_bench` and the new `mqtt_tls_bench` pipeline.
   - `mqtt_tls_bench` should end `OK (89 MQTT blocks)`: 3 connect blocks, 3 modes × 10 schemes × up / down, then
     TLS / mTLS × 13 key-exchange groups.
     - Each block is `#block <stage> <mode> [<scheme> <up|down>]`. The stage is `connect` (Stage 2: one row
       per connection) or `pipeline` (connections plus one row per message). The mode is the transport:
       `plain`, `TLS` (server-auth) or `mTLS` (mutual). So `#block pipeline mTLS ascon down` means pipeline
       connections over mutual TLS, sending Ascon-protected downlink frames.
     - `#watchdog <block>: hung during <step>` means that block made no progress for 8 s. The board rebooted and
       carried on with the next block. The block keeps its finished connections as `PARTIAL`.
     - `#stack` is the block's peak stack, and the `free_heap_B` column shows whether memory was running
       out.
   - A failed block keeps its reason as the row's status, e.g. `tls handshake failed: ...`.
   - The `#wifi` line in the log records the RSSI and channel. Keep the board in the same place between
     runs.
   - macOS may ask whether Mosquitto may accept incoming connections: allow it.
5. The optimised liboqs (part 4), once per board, next to the stock rows:

   ```bash
   bash pico/tests/qemu_liboqs/run.sh                                  # on the Mac, no board: must say OK
   python3 pico/run_benchmarks.py --lib liboqs                     # stock
   python3 pico/run_benchmarks.py --lib liboqs --keccak xkcp       # XKCP Keccak
   ```

   The ratio between these two runs is the real speed-up. The QEMU numbers only count instructions.
6. For a like-for-like comparison with the RP2040 study [16], add `--freq 133`: the core's default is
   200 MHz on the RP2040 and 150 MHz on the RP2350 [30]. To compare the two chips, run both at the
   same clock (e.g. `--freq 150`).

---

## 2. Stage by stage: what gets called

Timing clocks:
- Host C code uses `clock_gettime(CLOCK_MONOTONIC)`. The pipeline timer uses `CLOCK_UPTIME_RAW` on
  macOS, because the monotonic clock there only ticks every 1 µs.
- Python uses `time.perf_counter_ns()`.
- The Pico uses `micros()`. Pico "cycles" are µs × MHz, derived rather than counted.
- `openssl_sig_speed` counts real cycles, through `perf_event_open` on Linux and kperf on macOS
  (which needs sudo).

### Stage 1 `openssl`: `signatures/sig_speed.c`, OpenSSL 3.6.4 (+ oqs-provider)

1. `OSSL_PROVIDER_load(NULL, "default")` and `OSSL_PROVIDER_load(NULL, "oqsprovider")`. The second
   brings Falcon in from liboqs 0.16.0 (oqs-provider c174ed7); ML-DSA, SLH-DSA, RSA, ECDSA and
   Ed25519 are OpenSSL's own code.
   - The `round3` stage runs the same program with `OPENSSL_MODULES` set to the round 3 build
     (oqs-provider 36cafae on liboqs b196b57a). That build has MAYO-1/2/3/5, SNOVA I / III / V × K / B /
     S, and MQOM v3. It also builds the program on that liboqs directly (`-DSIG_LIBOQS`), which adds
     round 3 UOV.
   - Its rows go into the same Stage 1 table under their own Library label.
2. **keygen**: `EVP_PKEY_CTX_new_from_name(name)` → `EVP_PKEY_keygen_init` → `EVP_PKEY_CTX_set_params`
   (RSA bits, EC curve) once, outside the timer. **Timed: `EVP_PKEY_generate`** only.
3. **sign**: `EVP_MD_CTX_reset` → `EVP_DigestSignInit_ex(md = NULL for PQC, SHA-256 for RSA/ECDSA)`
   before each call, timed separately as `sign_setup`. **Timed: `EVP_DigestSign`** only. For RSA and
   ECDSA it hashes the message with SHA-256 first, which is part of the signature scheme.
4. **verify**: `EVP_DigestVerifyInit_ex`, timed separately as `verify_setup`. **Timed: `EVP_DigestVerify`**
   only. A failed verify is counted and reported as `VERIFY_FAIL`.
5. **Why setup is separate.** OpenSSL's one-shot `EVP_DigestSign` needs a fresh init every time, and a TLS
   handshake pays it too. So it isn't dropped, but it's reported next to the operation rather than inside
   it.
   - It costs about 1 µs for OpenSSL's own ML-DSA and ECDSA.
   - It costs about 207 µs for oqs-provider algorithms (Falcon, MAYO, SNOVA).
   - The sign / verify rows are then comparable with liboqs's: Falcon-512 is 154.5 / 24 µs through
     OpenSSL, against 154 / 24 µs direct.
6. **Sizes:** `EVP_PKEY_get_raw_public_key` / `get_raw_private_key` / `EVP_PKEY_get_size`, written
   to `.meta`.
7. **Output.** Per operation: mean, median, population std, min and max in ms, ops/s (= 1000 / mean) and
   cycles (mean and median). There are `SIG_N` iterations (default 100), the same for every algorithm
   and library.

### Stage 1 `liboqs`: `signatures/sig_speed.c -DSIG_LIBOQS`, liboqs 0.16.0

The same C file as the `openssl` stage, built on liboqs instead of OpenSSL (`liboqs_sig_speed`). The
message, loops, statistics, cycle counter and output format are identical, so the two libraries are timed
the same way.

1. `OQS_SIG_new("ML-DSA-44")` gives the algorithm's function table and its sizes (`#meta` line).
2. **keygen / sign / verify**, each timed per call: `OQS_SIG_keypair`, `OQS_SIG_sign`,
   `OQS_SIG_verify`. There is no per-call setup to pay, unlike EVP's `EVP_DigestSignInit_ex`.
3. `SIG_N` iterations (default 100), the same as every other library. A failed verify is reported as
   `VERIFY_FAIL`.

### Stage 1 `wolfssl`: `signatures/sig_speed.c -DSIG_WOLFSSL`, wolfSSL 5.9.4

`build_wolfssl.sh` configures wolfSSL with:
- ML-KEM, ML-DSA and SLH-DSA (SHA2 and SHAKE);
- native Falcon, double precision on 64-bit ARM (`--enable-experimental`, like Ascon);
- ARM assembly for AES (`--enable-armasm`) and for P-256 / RSA (`--enable-sp --enable-sp-asm`).

Signatures then run through the same C bench as OpenSSL and liboqs (`wolfssl_sig_speed`): the same
message, loops, `SIG_N`, statistics and output. The timed calls:
- **ML-DSA:** `wc_MlDsaKey_MakeKey` / `wc_MlDsaKey_SignCtx` / `wc_MlDsaKey_VerifyCtx`.
- **SLH-DSA:** `wc_SlhDsaKey_MakeKey` / `_Sign` / `_Verify`.
- **Falcon:** `wc_falcon_make_key` / `_sign_msg` / `_verify_msg`.
- **Ed25519:** `wc_ed25519_*`.
- **RSA and ECDSA:** `wc_MakeRsaKey` / `wc_ecc_make_key_ex`, and `wc_SignatureGenerate_ex` /
  `wc_SignatureVerify` over SHA-256. Two things about these:
  - `wc_SignatureGenerate_ex` is called with verify = 0. The plain `wc_SignatureGenerate` verifies every
    signature after making it (a fault-attack guard), which EVP doesn't do; that would add a verify to
    each sign.
  - Keys are initialised outside the timer.

wolfCrypt's own `benchmark -csv` still measures key exchange (ML-KEM, X25519) and 64-byte AES-GCM /
Ascon throughput. It runs each operation for at least 1 s (`BENCH_MIN_RUNTIME_SEC`) and prints the mean
and ops/s only:
- `bench_mlkem` / `bench_curve25519` for key exchange, `bench_aesgcm` / `bench_ascon` for AEAD
- `bench_aesgcm` → `wc_AesGcmEncrypt`
- `bench_ascon_aead` → `wc_AsconAEAD128_*`

It reports means only (no per-operation spread), so its rows in the customer form carry mean and
ops/s.

### Stage 1 reference: `signatures/reference/bench_template.c`

Each NIST submission with the standard layout (SDitH, QR-UOV, FAEST) is compiled with this template (HAWK and SQIsign run their own benches),
which calls the NIST API:
- `crypto_sign_keypair`;
- `crypto_sign` (returns message plus signature);
- `crypto_sign_open` (verifies).

`randombytes` reads `/dev/urandom`. `run_reference_benchmarks.py` builds, runs and aggregates.

### After Stage 1: `to_customer_form.py` and `versions()`

`to_customer_form.py` maps every Stage 1 output into the Pico `results.csv` columns, plus `min_us` /
`max_us` per operation and a `Library` column:
- the OpenSSL, liboqs and wolfSSL builds of the C bench, each a CSV + `.meta`;
- the reference summaries. The result is
`stage1_customer_form_<tag>.csv`.

`_common.versions()` records the environment in `versions_<tag>.json`:
- OS, kernel, Pi model and firmware, compiler;
- the OpenSSL CLI, oqs-provider, liboqs, Mosquitto, wolfSSL and ascon-c versions.

### `tls`: `tls_sweep.sh` + `mqtt_tls_timer` (OpenSSL 3.6.4), MQTT connections through the broker

**Server side:** the broker machine's Mosquitto listeners from `./run_all.sh --serve-broker`, the same
ones Stage 2 uses: per certificate, server-auth TLS on 18830+101+i and mTLS (`require_certificate`) on
18830+1+i. Their OpenSSL config accepts ML-KEM-512/768/1024, X25519MLKEM768 and X25519. The client runs on
another machine (`--broker IP`); a run against this machine's own address is recorded as local and not
counted.

**Client setup, once per mode × certificate × group** (the Stage 2 timer, as in `mtls`):
1. `OSSL_PROVIDER_load` (default + oqsprovider).
2. `SSL_CTX_new(TLS_client_method())`.
3. `SSL_CTX_set_min_proto_version(TLS1_3_VERSION)`.
4. `SSL_CTX_set1_groups_list("<group>")`: the only group offered, so the broker has to use it.
5. `SSL_CTX_load_verify_locations(CA.crt)` and `SSL_CTX_set_verify(SSL_VERIFY_PEER)`.
6. For mTLS: `SSL_CTX_use_certificate_file` and `SSL_CTX_use_PrivateKey_file`.

**Per iteration** (20 warm-up, then 200 by default):
1. TCP `connect()`, timed separately (`tcp_ms`).
2. **Timed (`tls_ms`): `SSL_new` → `SSL_set_fd` → `SSL_connect()`**, which performs the whole TLS 1.3
   handshake below. The sweep summarises `tls_ms` over the runs.
3. After the handshake, its bytes and socket calls are read:
   - `BIO_number_written` / `_read` for bytes (up = tx, down = rx);
   - a socket-BIO callback that counts writes and reads;
   - the kernel's TCP segment counters (`wire_stats.h`).
4. MQTT CONNECT → CONNACK, DISCONNECT, then `SSL_shutdown` and `SSL_free`: a full MQTT connection through
   the broker. No session resumption, so every handshake is a full one.

Each row has:
- **Times:** n, mean / median / std / min / max / p90 / p99 in ms, and handshakes/s.
- **Bytes:** `hs_tx_B` (up), `hs_rx_B` (down), `hs_B` (total), the medians over the runs.
- **Socket and TCP:** `writes` / `reads` (socket calls) and `tx_segs` / `rx_segs`.
- **On-wire estimate:** `wire_tx_B` / `wire_rx_B` / `wire_B`, which is the bytes plus 52 B of IPv4 + TCP
  headers per segment, without link-layer headers.

Between two machines the segment count shows the real split (about 1,448 B of payload per segment on
Ethernet / Wi-Fi).

What `SSL_connect()` does on the wire with X25519MLKEM768 [13] and ML-DSA [11] certificates:

```text
client                                                   server
ClientHello  key_share = ML-KEM-768 encaps key (1184 B) ‖ X25519 (32 B) = 1216 B  ─►
                          ◄─ ServerHello  key_share = ML-KEM ciphertext (1088 B) ‖ X25519 (32 B) = 1120 B
   (both sides now hold the hybrid shared secret -> TLS 1.3 key schedule; everything below is encrypted)
                          ◄─ EncryptedExtensions
                          ◄─ CertificateRequest                       (mTLS only)
                          ◄─ Certificate        server cert (ML-DSA public key + CA's ML-DSA signature)
                          ◄─ CertificateVerify  server signs the transcript hash   (ML-DSA sign)
                          ◄─ Finished
client verifies the CA signature on the cert and the CertificateVerify     (2 x ML-DSA verify)
Certificate + CertificateVerify  (mTLS only: client signs; server verifies 2 signatures) ─►
Finished ─►                                  SSL_connect() returns here
                          ◄─ NewSessionTicket(s)   (after the handshake, not timed; ~8.5 KB after ML-DSA mTLS)
```

So each handshake costs:
- one ML-KEM-768 keygen + decaps and one X25519 on the client; encaps + X25519 on the server;
- one signature per side that authenticates (the server always; the client too in mTLS);
- two signature verifies per certificate checked (the CA's signature on the certificate, and the
  CertificateVerify).

### `mtls` (Stage 2): `gen_certs.sh` + `mqtt_bench.py` + `mqtt_tls_timer.c`

1. **Certificates**, made by `gen_certs.sh` with OpenSSL 3.6.4 (+ oqs-provider for Falcon; round 3 MAYO and
   SNOVA with the round 3 provider, in `certs/round3/`). Per signature algorithm:
   - `openssl genpkey` makes the key of each of two CAs, then `openssl req -x509 -new` self-signs its
     certificate: `CA` (clients trust it) and `ClientCA` (the broker trusts it);
   - server and client each get `openssl genpkey` → `openssl req -new` (CSR) → `openssl x509 -req -CA`
     (SAN `localhost` / 127.0.0.1): `CA` signs the server's, `ClientCA` the client's. OpenSSL fills a certificate's
     chain from its own trust store, so with a single CA the broker also sent the CA the peer already holds
     (README finding 82).
2. **Broker**: one Mosquitto 2.1.2 process per certificate type.
   - The clients on the Pico W and on Linux also time their own crypto inside each handshake: key share, its
     completion, verify, sign. They are extra columns on every connection row (findings 83 and 94).
     - wolfSSL (Pico W, Pi): `hs_timing.c` with the linker's `--wrap`.
     - OpenSSL (Pi): `network/hs_timing_openssl.c`. `mqtt_tls_timer` defines the six libcrypto functions
       libssl calls during a handshake (`EVP_PKEY_keygen`, `EVP_PKEY_derive`, `EVP_PKEY_decapsulate`,
       `X509_verify_cert`, `EVP_DigestVerify`, `EVP_DigestSign`). The dynamic linker binds libssl to those
       copies, and each one times libcrypto's own. macOS binds libssl to libcrypto directly, so the Mac's rows
       have no such columns.
   - Settings: `per_listener_settings true`, `set_tcp_nodelay true` (no Nagle delay on the CONNACK after the
     TLS 1.3 session tickets), `cafile` = `ClientCA.crt` (only mTLS uses it), and `OPENSSL_CONF` with
     `Groups = ?X25519MLKEM768:?MLKEM512:...`: the Stage 2 group (the customer's X25519MLKEM768) plus the `tls`
     sweep's 16 others (`mqtt_bench.SWEEP_GROUPS`). `?` (OpenSSL 3.5+) skips a group this OpenSSL lacks,
     such as the oqs-provider ones without oqs-provider. Every client offers exactly one group
     (`SSL_CTX_set1_groups_list`, `wolfSSL_set_groups`), so Stage 2 and the pipeline always use X25519MLKEM768.
   - `log_type notice`: on the broker machine (`--serve-broker`), `follow_logs()` turns each accepted
     connection into one terminal line. The line gives the client's IP, the listener (certificate + TLS /
     mTLS), the client certificate for mTLS, and any handshake error. `--serve-broker --watch` adds a
     subscriber per broker that prints every message routed (a second delivery each).
   - Listeners:
     - plain MQTT on 18830 (`allow_anonymous true`);
     - mTLS on 18831+ (`tls_version tlsv1.3`, `cafile`/`certfile`/`keyfile`, `require_certificate
       true`, `use_identity_as_username true`);
     - server-auth TLS on 18931+ (`require_certificate false`).
3. **Client setup, once**: `tls_init()`.
   - OpenSSL: the same sequence as the `tls` stage, plus `SSL_CTX_set_ciphersuites` when `SUITE` is
     set.
   - wolfSSL: `wolfSSL_Init` → `wolfSSL_CTX_new(wolfTLSv1_3_client_method())` →
     `wolfSSL_CTX_load_verify_locations` → `wolfSSL_CTX_set_verify` →
     `wolfSSL_CTX_use_certificate_file` / `use_PrivateKey_file` → `wolfSSL_CTX_SetIORecv/Send`
     (byte-counting I/O callbacks) → `wolfSSL_CTX_set_cipher_list`.
4. **Per iteration** (5 warm-up, then 50):
   1. `socket()`, with `TCP_NODELAY` and a 10 s receive timeout.
   2. **Timed `tcp_ms`**: `connect()`.
   3. **Timed `tls_ms`**: `SSL_new` → `SSL_set_fd` → `SSL_connect()`. For wolfSSL: `wolfSSL_new` →
      `wolfSSL_set_groups` + `wolfSSL_UseKeyShare(X25519MLKEM768)` → `wolfSSL_connect()`.
   4. **Timed `mqtt_ms`**: `SSL_write`(MQTT 3.1.1 CONNECT, 23 B), then `SSL_read` until the 4-byte
      CONNACK arrives; return code 0 is checked.
   5. **Bytes**: OpenSSL's socket-BIO counters (`BIO_number_written` / `BIO_number_read`), or
      wolfSSL's I/O callbacks. These count the real bytes on the wire, split into handshake and MQTT.
      - The same hooks count socket writes / reads.
      - After CONNACK, the kernel's TCP segment counters are read (`wire_stats.h`).
      - The summary has, per combination:
        - times: mean / median / std / min / max of `tcp`, `tls`, `mqtt` and `total`;
        - bytes, as the median connection: `hs_tx_B` / `hs_rx_B` (handshake up / down), `mqtt_tx_B` /
          `mqtt_rx_B`, and `total_tx_B` / `total_rx_B` / `total_B` (the whole connect);
        - socket calls: `hs_writes` / `hs_reads`, `writes` / `reads`;
        - segments and the on-wire estimate: `tx_segs` / `rx_segs`, and `wire_tx_B` / `wire_rx_B` /
          `wire_B` (bytes + 52 B per segment).
      - The pipeline adds mean / median / std / min / max for seal, open, broker round trip and end to
        end, per message.
   6. DISCONNECT, `SSL_shutdown`, `close`.
5. A combination that fails (the broker can't load the certificate, the client can't parse it, the
   handshake is refused) becomes a row whose `status` gives the reason (plan: failures are results).

**Who talks to whom (`mtls`, `pipeline`).** Only across two machines. `run_all.sh` runs these stages
only with `--broker IP`, pointing at another machine running `--serve-broker` (below).
- By hand, `mqtt_bench.py --role both` still starts one Mosquitto per certificate type on
  `127.0.0.1`. That's useful as a smoke test, but its meta records `broker_local: true`, and
  `collate_results.py` doesn't count it.
- `round3`'s Stage 2 works like `mtls`, with certificates in `certs/round3/` and brokers from port 20830.
- The `tls` stage uses the same brokers: MQTT connections, one per handshake, over every key exchange.

**The broker on another machine (`--serve-broker` / `--broker IP`).**
- The broker machine runs `./run_all.sh --serve-broker`. That starts `mqtt_bench.py --role
  broker` twice, bound to all interfaces, and stops both on Ctrl-C:
  - round 2 and classical certificates from `certs/`: plain MQTT on 18830, mTLS on 18831+i, TLS on
    18931+i;
  - round 3 from `certs/round3/`, starting at 20830, loaded with the round 3 provider.
- The client machine runs `./run_all.sh --broker IP`. Each MQTT stage then connects instead of starting
  brokers:
  - `mtls` and `pipeline`: `--role client --host IP` on 18830 (the pipeline shares the `mtls` brokers);
  - `round3`: IP:20830.
  - The watchers subscribe on the same machine as the benches. Files get a `_remote` suffix.
- The certificates must be the same files on both machines (same CA). They name `localhost`, but
  `mqtt_tls_timer` checks only the chain (`SSL_VERIFY_PEER`, no host-name check), so any IP works.
  - `--dry-run` connects `openssl s_client` to the broker's ECDSA-P256 TLS port with the local CA, and
    fails when the CA differs.
  - With `--broker`, `run_all.sh` never generates certificates.

### `pipeline`: the same programs with `--messages N` (`MSGS` / `AEAD` / `PAYLOAD` / `DOWN` env)

The only place LoRaWAN / AES / Ascon are measured: as messages through the broker. Every scheme runs as
uplink frames and as downlink frames (`--dirs up,down`; `DOWN=1` makes the timer seal downlinks, MHDR 0x60,
Dir = 1). The Pico W runs the same pipeline in `mqtt_tls_bench` with `lora_aead.h`.

Each run is 1 warm-up + 3 recorded connections × N messages (default 200 from `run_all.sh`). After
CONNACK, `pipeline()` in `mqtt_tls_timer.c` does the following:

1. SUBSCRIBE to `pqc/pipe/<pid>`, QoS 0, and wait for SUBACK.
2. For each message:
   1. **seal_us**: `app_seal()` protects the 51-byte payload with the chosen scheme and direction (part 3).
   2. Build the MQTT PUBLISH (fixed header ‖ topic ‖ frame) and `SSL_write` it. The TLS 1.3 record
      layer encrypts it again with the negotiated suite (`TLS_AES_256_GCM_SHA384` by default).
   3. Mosquitto decrypts the record, routes it to the subscriber (the same client), and re-encrypts
      it on that connection.
   4. **rtt_us**: `SSL_read` until our PUBLISH comes back.
   5. **open_us**: `app_open()` verifies and decrypts; the payload is compared byte for byte.
   6. tx_B / rx_B: socket bytes for this message.
3. Across all messages, `mqtt_bench.py` summarises seal and open means, RTT median, and the
   end-to-end median / p90 / mean.

**Why the client sends to itself.** The timed client both publishes and subscribes to `pqc/pipe/<pid>`,
so the broker delivers each message back to it. Send and receive are timed on one clock, so the
round trip is exact even when the broker is on another machine. Separate publisher and subscriber
processes would need synchronised clocks for a one-way time, which two Pis don't have.

**Seeing the messages arrive (`--watch`).** `mqtt_bench.py --messages 5 --watch` also starts
an independent subscriber per broker: `mqtt_tls_timer` in watch mode, with its own client ID, on the
server-auth TLS listener, or the plain one for the plain broker. It prints every message the broker
delivers to it:

```text
[watch MLDSA44] 02:24:44.909976  pqc/pipe/76241  64 B  FCnt 2  -> {"seq":2,"temp_c":21.5,"rh":48}  (LoRaWAN-1.1 AES-128-CTR+2xCMAC: verified)
```

- The watcher holds the same keys as the publisher (`APP_KEYS`, generated per run). It finds the scheme
  whose MIC / tag verifies, then shows the decrypted reading. The topic has no scheme name in it, so
  the bytes on the wire are identical to a timing run.
- Run without `APP_KEYS` (e.g. a watcher you start by hand), it sees what the broker and anyone else
  on the network see: the reading in clear for `none`, ciphertext for every protected scheme.
- A watcher is a second delivery for the broker.
  - On the Mac it adds about 3–7 µs to the median broker round trip (19–26 µs → 22–30 µs); on a real
    network, where the round trip is milliseconds, that's under 1%.
  - `run_all.sh` watches by default, writing `results/pipeline_watch_<tag>.log` and
    `results/mqtt_watch_<tag>.log`. `--no-watch` turns it off for runs where the broker round trip is
    the number you report.
- By hand, against a broker started with `--role broker`:

  ```bash
  SUB='pqc/pipe/#' network/mqtt_tls_timer <broker> <TLS port> 1 0 certs/MLDSA44/CA.crt
  ```

### `pico`: `pico/run_benchmarks.py` + the sketches

1. **Detect the board.** A 1200-baud "touch" on `/dev/cu.usbmodem*` drops the running sketch into
   BOOTSEL. The mounted drive (`RPI-RP2` = RP2040, `RP2350`) and its `INFO_UF2.TXT` identify the chip.
2. **Compile**: `arduino-cli compile --fqbn rp2040:rp2040:rpipico|rpipico2 --build-property
   compiler.{c,cpp}.extra_flags=<flags>`. Flags such as `-DPICO_VARIANT_44` pick the parameter set
   inside a family folder; `-DLB_ALG=…` picks the liboqs algorithm.
   - `mqtt_tls_bench` builds for `rpipicow` / `rpipico2w`, the Wi-Fi boards.
   - First the runner writes a header into the build folder: `WIFI_SSID`, `WIFI_PASS` and `BROKER`
     from the environment, and `certs/<sig>`'s CA, client certificate and key as DER.
   - It deletes the header after compiling, and the build folder after flashing, because the firmware
     holds the password and the key.
3. **Flash**: byte-copy the `.uf2` onto the BOOTSEL drive.
4. **Capture**: pyserial reads the serial port until the sketch prints `=== done`, or the entry's
   timeout expires.
5. **Parse**: the log is turned into rows, which are merged into `logs/results.csv` (a re-run
   replaces only its own rows).
6. **Status**: a hang or reset becomes `RUNTIME_MEMORY_FAIL` or `STACK_OVERFLOW`; a board that can't
   fit the algorithm is skipped with its reason.

Inside the sketches:

| Sketch | Timed calls (each wrapped in `micros()`) | Memory measurement |
|---|---|---|
| family sketches (ML-DSA, Falcon, SLH-DSA, HAWK, FAEST, SDitH, QR-UOV, UOV-Ip) | the algorithm's own API, e.g. `PQCP_MLDSA_NATIVE_MLDSA44_C_keypair / _signature / _verify` (mldsa-native), PQClean `crypto_sign_keypair / crypto_sign_signature / crypto_sign_verify` | `rp2040.getFreeStack()`, `getFreeHeap()` |
| `liboqs_bench` | `OQS_SIG_keypair / OQS_SIG_sign / OQS_SIG_verify` (liboqs 0.16.0, `OQS_EMBEDDED_BUILD`; with `--keccak xkcp` its Keccak is XKCP assembler, part 4. Round 3 MAYO / SNOVA / MQOM / UOV: liboqs main, `OQS_MEMOPT_BUILD`) | painted "big stack": peak = bytes whose fill pattern was overwritten |
| `wolfssl_bench` | `wc_MlDsaKey_MakeKey / SignCtx / VerifyCtx`, `wc_SlhDsaKey_*`, `wc_ecc_make_key_ex / sign_hash / verify_hash`, `wc_ed25519_*`, `wc_MakeRsaKey / wc_RsaSSL_Sign / Verify` | free stack / heap |
| `mqtt_tls_bench` (Pico W) | per connection, as `mqtt_tls_timer.c`: `WiFiClient::connect` (TCP), `wolfSSL_connect` (TLS 1.3, X25519MLKEM768 key share, certificate verify; mTLS also signs), MQTT CONNECT → CONNACK. Pipeline: SUBSCRIBE, then per message seal (`lora_aead.h`: LoRaWAN CTR via `br_aes_ct_ctr_run` + CMAC built on `br_aes_ct_cbcenc_run`; GCM via `br_gcm_*` (BearSSL `aes_ct`); Ascon via ascon-c `crypto_aead_encrypt` (`armv6m_lowsize`)), PUBLISH → the broker's echo, open + verify; uplink and downlink frames. Bytes and socket calls are counted in the wolfSSL I/O callbacks | wolfSSL's peak heap (allocator hooks) and the painted stack's peak, per block; known-answer checks first |

---

## 3. LoRaWAN, AES, Ascon, GCM and CMAC

### 3.1 What each one is

| Name | What it is | Gives you |
|---|---|---|
| **AES** | A *block cipher*: a keyed permutation of one 16-byte block (key 128 or 256 bit). On its own it encrypts nothing longer than 16 bytes; it needs a *mode*. | a building block |
| **CTR** (AES-CTR) | A mode: encrypt a counter block with AES and XOR the output into the data. | **confidentiality only**; flipping a ciphertext bit flips the same plaintext bit, and nothing notices |
| **CMAC** (AES-CMAC, RFC 4493 [7]) | A mode: CBC-chain AES over the message, the last block is the tag. | **integrity / authentication only**; the data stays readable |
| **GCM** (AES-GCM) | An *AEAD* mode: CTR for encryption plus GHASH (a multiply in GF(2^128)) for the tag, in one pass, with a nonce. | confidentiality **and** integrity together; header bytes can be authenticated without being encrypted (AAD) |
| **Ascon-AEAD128** | A different *AEAD* altogether (NIST SP 800-232 [8], Aug 2025), built on a 320-bit permutation instead of AES. It was designed for small, AES-less hardware. | the same as GCM: confidentiality + integrity + AAD |
| **LoRaWAN** | A *protocol* that uses AES-128 in specific modes: **CTR to encrypt the payload, CMAC for the 4-byte MIC**, ECB for joins and key derivation. | encrypt-then-MAC, with two different keys |

So "GCM" and "CMAC" answer different questions. CMAC only proves the frame wasn't changed. GCM
proves that *and* hides the payload. LoRaWAN gets the same two properties as GCM by combining CTR
with CMAC, and uses **two keys**:
- the application key encrypts, so only the application server can read the payload;
- the network key MACs, so the network server can check frames it cannot read.

GCM or Ascon with one key would give the network server either both abilities or neither. That is
why LoRaWAN is not simply AES-GCM.

In this repo, GCM appears in two places:
- as a payload scheme (`aes128gcm` / `aes256gcm`), protecting the LoRaWAN frame in place of LoRaWAN's
  own scheme;
- inside TLS 1.3, where `TLS_AES_256_GCM_SHA384` protects every MQTT record between client and
  broker.

CMAC appears only in LoRaWAN (the MIC) and in the `cmac` self-test.

**In the code** (`network/app_aead.c`; the Pico's `mqtt_tls_bench/lora_aead.h` does the same on BearSSL,
byte for byte). Both run only in the pipeline, so every protected message travels through the broker. Every scheme
protects the same frame: a 9-byte header (MHDR, DevAddr, FCtrl, FCnt's low 16 bits, FPort), then the payload.

LoRaWAN 1.0.x and 1.1:
- **CTR:** `EVP_aes_128_ctr` under AppSKey. The IV is the counter block
  A_1 = 0x01 ‖ 0⁴ ‖ Dir ‖ DevAddr ‖ FCnt (32 bit) ‖ 0x00 ‖ 0x01, and OpenSSL steps it to A_2, A_3, ...
  (spec 4.3.3). The keystream is XORed onto the payload.
- **CMAC MIC:** `EVP_MAC` "CMAC" over B0 ‖ header ‖ encrypted payload, where
  B0 = 0x49 ‖ 0⁴ ‖ Dir ‖ DevAddr ‖ FCnt ‖ 0x00 ‖ length. That is encrypt-then-MAC.
  - 1.0.x keeps 4 bytes of the CMAC under NwkSKey.
  - 1.1 uplinks keep 2 bytes of CMAC(SNwkSIntKey, B1 ‖ ...) and 2 bytes of CMAC(FNwkSIntKey, B0 ‖ ...).
    1.1 downlinks keep 4 bytes of CMAC(SNwkSIntKey, B0 ‖ ...). B0's ConfFCnt field is 0, as no ACK is sent.
  - The CMAC key schedule is set up once per key; each message only re-inits.
- **Direction:** Dir is 0 for an uplink (MHDR 0x40) and 1 for a downlink (0x60). `app_open` reads it from
  the MHDR.

GCM and Ascon (our alternatives to LoRaWAN's scheme):
- **GCM:** `EVP_aes_{128,256}_gcm` under AppSKey. The 12-byte nonce is DevAddr ‖ FCnt (all 32 bits) ‖ Dir ‖ 0³.
  The 9-byte header is AAD (authenticated, not encrypted), and there is a 16-byte tag.
- **CCM:** `EVP_aes_{128,256}_ccm` (BearSSL `br_ccm` on the Pico): CTR encryption plus a CBC-MAC, the AEAD
  mode of Bluetooth LE, Zigbee and IEEE 802.15.4. The 13-byte nonce is DevAddr ‖ FCnt ‖ Dir ‖ 0⁴; header as
  AAD, 16-byte tag. CCM needs the payload length before it starts, which a fixed-size frame always has.
- **Ascon-AEAD128:** the same frame, with a 16-byte nonce DevAddr ‖ FCnt ‖ Dir ‖ 0⁷, via ascon-c
  `crypto_aead_encrypt`. NIST standardised only this 128-bit-key AEAD (SP 800-232). The "256" in the Ascon
  family is Ascon-Hash256, a hash; the one longer-key AEAD, Ascon-80pq (160-bit key), was left out of the standard.

Key size, 128 vs 256 bits, per AES mode:
- **CTR:** LoRaWAN defines AES-128 only. `aes256ctr` is its 1.0.x frame with AES-256-CTR and an AES-256-CMAC
  MIC (NIST SP 800-38B allows any AES key); the MIC key is NwkSKey ‖ the second network key. It isn't
  standard LoRaWAN; it shows what a 256-bit key costs in LoRaWAN's own construction. `lorawan11_256` does the same
  for the 1.1 frame: AES-256-CTR, and the 1.1 MIC rules (two CMACs per uplink, one per downlink) with AES-256-CMAC
  keys nwk ‖ nwk2 and nwk2 ‖ nwk.
- **GCM / CCM:** 128 and 256 each. AES-256 runs 14 rounds instead of 10, so expect about 40 % more time per
  block on chips without AES instructions (the Pico).
- All run on the same frame, so the byte overhead stays 4 B (CTR + MIC) or 16 B (AEAD tag) either way.

The OTAA join (CMAC MICs, AES-ECB key derivation) is not measured: it was timed only locally, so it was
removed on 29 Sep; measuring it again means sending the join messages through the broker.

**Nonce rule.** CTR, GCM and Ascon all break if one key ever sees the same counter twice: the XOR of two
ciphertexts reveals the XOR of the plaintexts, and GCM also leaks its authentication key. LoRaWAN avoids this
by rejoining (new keys) before the frame counter wraps. The benches follow the same rule:
- The pipeline's FCnt runs on across connections instead of restarting at 1. Dir in A_i, B0 and the nonce keeps
  uplink and downlink frames apart, as LoRaWAN's two counters do.
- The Pico's pipeline uses one FCnt for the whole run (54 pipeline blocks, about 43,000 frames: under 65,536).
- Each pipeline process has its own DevAddr, so processes that share the watch keys still never repeat a
  nonce.
- Before 28 Sep the benches reused counters under one key. Only synthetic data was affected, and no timing
  or byte count changed.

**Where a network server such as ChirpStack fits.** With real radios the chain is:
- the device (the Pico) sends over LoRa to a gateway;
- the gateway forwards packets to the network server (via ChirpStack's gateway bridge / MQTT forwarder);
- the network server checks the MIC with the network key, removes duplicates, tracks FCnt and answers
  joins;
- the application server decrypts with AppSKey and publishes the reading to an MQTT broker, for the
  application.

In this repo there is no radio or gateway. `app_open` stands in for the network and application servers
(MIC check, then decrypt), and our client talks to Mosquitto directly. So ChirpStack changes none of the
numbers measured here.

It would matter for two things:
- An interop check that a real network server accepts our frames. The self-test already uses published
  vectors, including brocaar/lorawan, the LoRaWAN library by ChirpStack's author.
- The MQTT links of a real deployment (gateway ↔ network server, network server ↔ application). These are
  where Stage 2's PQ TLS would sit. Whether ChirpStack's own TLS stack accepts PQ certificates is untested.

### 3.2 What each LoRaWAN version includes

| | 1.0.3 | 1.0.4 | 1.1 |
|---|---|---|---|
| Payload encryption (FRMPayload) | AES-128-CTR (A_i blocks), AppSKey | **same** | same |
| Uplink MIC | 4 B of CMAC(NwkSKey, B0 ‖ frame) | **same** | 2 B of CMAC(SNwkSIntKey, B1 ‖ frame) ‖ 2 B of CMAC(FNwkSIntKey, B0 ‖ frame): two CMACs |
| MAC commands in FOpts | sent in clear | sent in clear | encrypted with NwkSEncKey |
| Root keys | AppKey | AppKey | AppKey + NwkKey |
| Session keys from a join | 2 (NwkSKey, AppSKey) | 2 | 4 (FNwkSIntKey, SNwkSIntKey, NwkSEncKey, AppSKey) + 2 join-server keys |
| DevNonce | random | **counter, kept in non-volatile memory** | counter |
| JoinNonce (AppNonce in 1.0.3) | no device rule in the spec; LoRaMac-node rejects only a repeat of the last value | a counter; the device should check that it increases (LoRa Alliance TR, 2020; optional in LoRaMac-node, `USE_10X_JOIN_NONCE_COUNTER_CHECK`; our 1.0.4 join enforces it) | must increase (spec) |
| Join-Accept MIC covers | the accept fields | the accept fields | the accept fields **+ JoinEUI + DevNonce** (binds it to the request) |
| Frame counters | 16 or 32 bit (32 recommended) | **32 bit, persistent** (ABP counters never reset) | 32 bit; separate network/application downlink counters |
| Names | AppEUI, AppNonce | JoinEUI, JoinNonce | JoinEUI, JoinNonce |

Sources [1, 2, 3, 4]: Semtech LoRaMac-node `LoRaMacCrypto.c`
([GitHub](https://github.com/Lora-net/LoRaMac-node)); The Things Network,
["What's new in LoRaWAN 1.0.4"](https://www.thethingsnetwork.org/article/whats-new-in-lorawan-104-1);
the [LoRaWAN L2 1.0.4 specification](https://lora-alliance.org/wp-content/uploads/2021/11/LoRaWAN-Link-Layer-Specification-v1.0.4.pdf).

**What that means for the benches:**
- Per message, 1.0.3 and 1.0.4 run the identical computation, so there is one `LoRaWAN-1.0.x` row for
  both. Timing them separately would time the same code twice.
- The versions differ in the join, which is not measured (see above).
- 1.1's extra per-message cost is the second CMAC.

### 3.3 Where AES and Ascon sit relative to LoRaWAN

LoRaWAN **already is** AES: AES-128 is the only cipher the spec allows, at every version. AES-256
and Ascon are **not** part of LoRaWAN, so an AES-256-GCM or Ascon row is not a "LoRaWAN mode".
There are two ways to read those rows:

1. **Replacement** (what the pipeline measures, on the host and the Pico W). The same 9-byte LoRaWAN header and
   the same payload, protected by AES-GCM or Ascon *instead of* LoRaWAN's CTR + CMAC. This answers
   the plan's question: would a stronger (AES-256) or lighter (Ascon) scheme cost more than
   LoRaWAN's AES-128? The trade-off it shows is 12 more bytes on air (a 16-byte tag against a 4-byte
   MIC) and one key instead of two.
2. **Layering** (end-to-end application encryption). A device can encrypt its reading with Ascon or
   AES-GCM first, then hand the ciphertext to LoRaWAN as FRMPayload. The costs then **add up**:
   LoRaWAN's CTR + CMAC plus the application AEAD, and 13 + 16 + nonce bytes on air. This keeps the
   payload unreadable even to a compromised application server. The benches don't measure this
   combination yet; the two parts can be added from the rows above.

On the MQTT side (network server ↔ broker ↔ application) LoRaWAN is gone. That link is protected by
TLS 1.3, whose record layer is AES-GCM, which is what the `mtls` and `pipeline` stages measure.

**Quantum:** Grover's algorithm roughly halves the effective strength of a symmetric key. AES-128
still counts as NIST security category 1, which is why the plan asks about AES-256. LoRaWAN cannot
use AES-256 without a spec change.

---

## 4. Optimising the Pico code

"Unoptimised" means portable C that was never tuned for a Cortex-M. On a 32-bit M0+ the biggest waste
is Keccak (the SHA-3 / SHAKE permutation), which ML-DSA, SLH-DSA-SHAKE, ML-KEM and others spend
much of their time in. The portable code works on 64-bit lanes, which a 32-bit core has to emulate
with pairs of instructions.

### 4.1 What was done: XKCP assembler Keccak in liboqs (`--keccak xkcp`)

- `pico/sketches/liboqs_bench/keccak_swap.sh` copies the Pico `liboqs.a` and replaces two objects:
  - liboqs's Keccak (`KeccakP-1600-opt64.c`);
  - SLH-DSA's own copy (`sha3_f1600.c`).
- They are replaced with XKCP's hand-written assembler [27], which is public domain:
  - RP2040: `KeccakP-1600-u2-32bi-armv6m-le-gcc.s` (ARMv6-M, bit-interleaved, two rounds unrolled);
  - RP2350: `KeccakP-1600-inplace-32bi-armv7m-le-gcc.s` (ARMv7-M; the M33 is ARMv8-M Mainline, a
    superset).
- `xkcp/keccak_glue.c` supplies the two entry points liboqs expects that XKCP leaves out. It also adapts
  SLH-DSA's `keccak_f1600(uint64_t[25])`.
- Nothing else in liboqs changes. XKCP is fetched at a pinned commit into `~/.cache/iot-pqc`.
- `make_liboqs_lib.sh` with `LIBOQS_KECCAK=xkcp` builds `~/.cache/iot-pqc/arduino-libs-xkcp/liboqs`.
  The runner's `--keccak xkcp` does this for you and labels the rows "(liboqs+XKCP Keccak)".

### 4.2 How it was checked without a board

`pico/tests/qemu_liboqs/run.sh` runs the real Pico libraries in QEMU 11.1.1:
- M0+ code on `mps2-an385`, a Cortex-M3 board, which runs ARMv6-M code unchanged;
- M33 code on `mps2-an505`.

Per build, `test.c` checks:
- the SHA-3 / SHAKE known answers (FIPS 202);
- one-shot vs incremental hashing, and 4-way vs 1-way;
- keygen / sign / verify for 8 algorithms under the same deterministic RNG.

A variant passes only if every signature is **byte-identical** to the stock build's. SysTick under
`-icount` counts instructions, and a table goes to `pico/logs/qemu_liboqs_keccak.csv`.

Three harness details matter if you change it:
- liboqs is `-fPIC`, so the linker script must copy `.got` into RAM;
- arduino-pico's newlib needs lock stubs;
- the M33 run enables the FPU.

### 4.3 Result (instructions, stock → XKCP; arduino-pico 6.1.1, GCC 16.1.0)

Each figure is stock instructions divided by XKCP instructions, so above 1× means faster; the full
table is README finding 24.

| | RP2040 (M0+) | RP2350 (M33) |
|---|---|---|
| Keccak | 1.39× | 1.48× |
| ML-DSA-44 sign | 1.10× | 1.24× |
| SLH-DSA-SHAKE-128f sign | 1.18× | 1.30× |
| Falcon, MAYO, SNOVA, SLH-DSA-SHA2 | ≈1.00× | ≈1.00× |

GCC 16.1 made the stock M0+ Keccak about 9% leaner than GCC 14.3 did, which narrowed the RP2040 gap
from 1.51× to 1.39×.

These are instructions, not time. On the M0+, loads and taken branches take 2 cycles, and code runs
from flash through a cache that QEMU doesn't model. The board run with and without `--keccak xkcp`
gives the real ratio.

### 4.4 Other knobs (in the runner, not yet measured on a board)

- `--opt O|O2|O3|Ofast`: the compiler level for the sketch and the Arduino core. The default is `-Os`,
  which favours size. Precompiled liboqs and wolfSSL already use `-O3`.
- `--freq <MHz>`: the CPU clock. It isn't a code optimisation, but every number depends on it: the
  defaults are 200 MHz (RP2040) and 150 MHz (RP2350).

### 4.5 What is left, and what it would take

| Idea | Expected gain | Effort / risk |
|---|---|---|
| pqm4's Cortex-M4 assembler [24] (ML-DSA, ML-KEM and Falcon NTT / arithmetic) on the RP2350: the M33 has the same DSP instructions | likely the largest for lattice schemes (pqm4's own benchmark tables compare its M4 code with the reference builds) | port and test per scheme; none of it runs on the RP2040 (ARMv6-M) |
| RP2350 SHA-256 accelerator [29] for SLH-DSA-SHA2 | large for SLH-DSA-SHA2, which is almost all SHA-256 | a driver for the accelerator inside liboqs's SHA-256; RP2350 only |
| Hot code in SRAM instead of XIP flash (`__not_in_flash_func`) | avoids flash-cache misses, mostly on the RP2040 (16 KB cache) | small; measurable only on a board |
| The same Keccak swap in the per-algorithm sketches (PQClean / mldsa-native `fips202.c`) | as 4.3, for those rows | one glue per sketch family; liboqs already covers the same algorithms |
| The second core (both chips have two) | up to 2× on parallel parts (e.g. 4-way Keccak in ML-DSA) | invasive; changes what is being compared |

For the customer's comparison, keep the stock rows as the baseline and report optimised rows next to
them (the labels keep them apart). "Portable library as shipped" and "tuned for this chip" are both
useful, and different.
