# `reference/` — polyglot benchmarks of NIST Onramp signatures

This directory runs each algorithm's **own NIST submission C reference**
through a single generic timing harness (`bench_template.c`) and aggregates
the results into the percentile CSV that `to_customer_form.py --summary` reads, so the
Stage 1 table shows them next to the OpenSSL and liboqs rows.

Use this for algorithms that **liboqs doesn't have** — FAEST, HAWK, QR-UOV, SDitH, SQIsign. MQOM's round 3 code is in liboqs main (`run_all.sh` round3 stage).
Algorithms liboqs has are measured by `run_all.sh`'s `liboqs` stage (`liboqs_sig_speed`, the same C
timing code as the OpenSSL bench).

## Why this approach

Every NIST signature submission ships a `Reference_Implementation/`
directory whose `api.h` declares the same three functions:

```c
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
```

`bench_template.c` calls these three functions in a timing loop and writes
CSV to stdout. `run_reference_benchmarks.py` compiles the template against
each algorithm's `.c` files, runs the binary, and aggregates output into
percentile rows.

The timing loop is C (`bench_template.c`); Python only compiles, runs and collects. Just `cc` and `subprocess`.

## Run everything (June 2026)

Both platforms have a one-shot runner in `signatures/`. Each stage is
independent — one algorithm failing doesn't stop the rest — and all results
upsert into `../results/*.csv` in the schema `to_customer_form.py` reads.

```bash
# from the repo root; one script for macOS (Apple Silicon) and Raspberry Pi / Linux arm64
./run_all.sh --lib reference                  # apt/brew deps + every reference algorithm + CSVs
./run_all.sh --only hawk,sqisign              # subset
./run_all.sh --lib reference --no-deps        # skip apt / brew
sudo -E ./run_all.sh --only openssl --no-deps # macOS: real cycle counts (kperf needs root)
```

Stages: `openssl` (EVP cycle benchmark), `sdith`, `faest` (generic harness),
`hawk` (native bench, parsed), `sqisign` (cmake, parsed),
`qruov` (NIST package download + generic harness), `tls` (TLS **and mTLS**
handshake-latency sweep: builds `network/tls_handshake_timer`,
self-hosts `openssl s_server`, sweeps every complete `certs/<sig>/` × KEM
group in both modes → `results/tls_handshake_pure.csv`; `TLS_ITERS=N`
overrides the 200-iteration default). Combos the local OpenSSL can't do
(e.g. MLKEM groups without OpenSSL 3.5/oqs-provider) are skipped, not fatal.

Not in the run-alls (need two hosts / a broker, so they stay manual):
`network/benchmark_tls_handshake.py` (s_client against a remote
server, `--mode TLS|MTLS`), the MQTT end-to-end experiments in
`experiments/`, and `benchmark_tls_bytes.py` / `benchmark_e2e_latency.py`.

### Installation prerequisites

| Platform | Packages | Notes |
|---|---|---|
| Pi (64-bit OS) | `sudo apt install build-essential cmake libssl-dev python3 unzip wget` | the run-all script does this for you |
| macOS | `brew install openssl@3 cmake` | scripts export `CPATH`/`LIBRARY_PATH` from `brew --prefix openssl@3`, so no per-command `-I/-L` flags needed |

No meson/ninja (FAEST is flattened), no jq, no GMP (SQIsign vendors mini-gmp).

### Where the clock cycles come from

| Tool | Pi / Linux | macOS (Apple Silicon) |
|---|---|---|
| `openssl_sig_speed` (EVP/oqs-provider algos) | `perf_event_open` hardware counter; run `sudo sysctl kernel.perf_event_paranoid=1` once | private **kperf** framework (same technique as SQIsign's bench); **requires sudo**, fails soft to cycles=0 |
| generic harness (`bench_template.c`: SDitH, FAEST, QR-UOV) | `perf_event_open` user-space cycles per call, as `openssl_sig_speed` (`mean_cycles` / `median_cycles`) | wall-clock only; cycles = 0 |
| HAWK `bin/speed` | ms/µs natively | ms/µs natively |
| SQIsign `benchmark_lvlN` | ms (`NO_CYCLE_COUNTER` build — mandatory, see gotchas) | ms (`NO_CYCLE_COUNTER`, used by the script) or megacycles (default build, needs sudo + `--cpu-mhz`) |

The cycles column being 0 never invalidates the timing columns.

To populate the cycles column (you'll see `[i] kperf init failed (re-run
with sudo for real cycles) - cycles=0` or the perf equivalent otherwise):

```bash
# macOS (Apple Silicon) - kperf is a private API and needs root:
sudo -E ./run_all.sh --only openssl --no-deps     # from the repo root
# or run the binary directly (from signatures/):
sudo ./openssl_sig_speed 200 ED25519 EC:P-256 RSA:2048 > ../results/openssl_sig_speed_mac.csv

# Raspberry Pi / Linux - one-time sysctl, then no sudo needed for the run:
sudo sysctl kernel.perf_event_paranoid=1
./run_all.sh --only openssl --no-deps
```

Note: under `sudo` the oqs-provider env var doesn't survive unless you pass
it through, e.g. `sudo OPENSSL_MODULES=$OPENSSL_MODULES ./openssl_sig_speed ...`
if you're benchmarking the PQC algorithm names.

## Manual workflow

```bash
cd signatures/reference

# 1. HAWK (round 2, withdrawn in round 3): clone its source tree.
./clone_algos.sh

# 2. The round 3 code of SDitH, FAEST, SQIsign and QR-UOV (the same code as the Pico's), fetched and built once
#    per machine into ~/.cache/iot-pqc/ref-r3 ($IOT_PQC_CACHE), out of the repo:
./setup_round3.sh SDitH QR-UOV FAEST SQIsign

# 3. Benchmarks through the generic harness (--iterations, default 200; run_all.sh passes SIG_N)
python run_reference_benchmarks.py --algos SDitH FAEST SQIsign QR-UOV

# 4. HAWK runs its own benchmark binary; capture the output and feed it to parse_native_output.py (below).

# 5. The Stage 1 table: ../../run_all.sh builds results/stage1_customer_form_<tag>.csv from these CSVs.
```

### Build-strategy matrix (round 3, 7 Oct 2026)

| Algo    | Source (setup_round3.sh) | How the generic bench gets it |
|---------|--------------------------|-------------------------------|
| SDitH v3 | NIST round 3 package (`sdith3_submission_package.zip`), 12 sets | each set's CMake builds `libsdith` / `libsha3` / `libaes`; the bench compiles `generator/sign.c` (the NIST API) |
| QR-UOV  | NIST round 3 package (`QR_UOV - Round3.zip`), 15 sets | one `ref/` tree, `-DQRUOV_PARAM_<set> -DPRG_IS_AES=1` (its GNUmakefile's default), `-lcrypto` |
| FAEST 3.0 | faest-ref `v3.0.0`, 12 sets | its own meson build (meson + ninja); each set's `crypto_sign.c` against `libfaest_no_random.a` / `libfaest.a`, `-lcrypto` |
| SQIsign | the-sqisign `f417ebd`, levels I / III / V | CMake ref build (64-bit field arithmetic on a 64-bit host); per level an `api.h` namespaced as its NIST API library, and the level's archives (`libs.txt`) |
| HAWK    | `native-bench` (round 2) | builds its own `tests/speed.c` benchmark |

`algos.json` writes the cache as `{CACHE}`; `run_reference_benchmarks.py` resolves it on each machine. On macOS it
also maps `explicit_bzero` to `bzero` (QR-UOV uses it; macOS lacks it).

### Native benchmark recipes

For algos where `build_strategy != "generic-bench"`, the runner skips with
a helpful message. Run each algorithm's own benchmark manually:

**HAWK** (Reference_Implementation is a single flat source tree built once; tests/speed.c covers all variants. The repo's Makefile hardcodes `CC=c99` which on macOS is the POSIX wrapper that rejects GCC-style flags - override it):
```bash
cd signatures/reference/HAWK/Reference_Implementation
make CC=clang                               # macOS; on Pi/Linux: make CC=cc
./bin/speed > ../../hawk_results.txt        # built into bin/, not tests/
# bin/speed prints keygen in ms and sign/verify in us (no cycle conversion
# needed). Parse + upsert into the summary CSV:
python ../../parse_native_output.py --algo HAWK --input ../../hawk_results.txt
#
# Note: `make` at the HAWK top-level runs build.py which ALSO tries to
# build the AVX2 optimized path; that step fails on arm64 (x86 asm) but
# Reference_Implementation/ still builds, so skip the top-level Makefile
# and go straight into Reference_Implementation/.
```

## Output files

Written to `../results/` (the repo's top-level `results/` directory):

| File | Schema | Contents |
|---|---|---|
| `sig_summary_reference.csv` | `label,n,mean_ms,stdev_ms,p50_ms,p90_ms,p99_ms,min_ms,max_ms,mean_cycles,median_cycles` (cycles: generic-harness rows on Linux; blank otherwise) | Percentile table, one row per `{variant} {sign|verify}` |
| `sig_raw_reference.csv`     | `label,iteration,latency_ms,cycles` | Per-iteration samples |
| `sig_meta_reference.csv`    | `friendly_name,family,status,nist_level,pk_bytes,sk_bytes,sig_bytes` | Static metadata captured from `bench_template.c`'s stderr |

## Per-algorithm notes

Where to get the source and any gotchas:

| Algorithm | URL | Variants in `algos.json` | Notes |
|---|---|---|---|
| **HAWK**    | https://hawk-sign.info/  | HAWK-256/512/1024 | Pure C, builds cleanly with `cc -O3`. The fastest one to try first. |
| **SDitH**   | https://sdith.org/ (NIST round 3 package) | v3 (VOLE-in-the-head): cat1/3/5 × fast/short × with/without cipher PoW (12) | `setup_round3.sh SDitH` |
| **QR-UOV**  | NIST CSRC round 3 package | 1/3/5 × q127L3, q31L3, q127L10, q31L10, q7L10 (15) | `setup_round3.sh QR-UOV`; large public keys, keygen can be slow |
| **FAEST**   | https://faest.info/ (faest-ref v3.0.0) | FAEST(-EM)-128f/s 192f/s 256f/s (12) | `setup_round3.sh FAEST`; meson + ninja; links OpenSSL `libcrypto` for AES |
| **SQIsign** | https://sqisign.org/ (the-sqisign f417ebd) | I / III / V (p324, p500, p664) | `setup_round3.sh SQIsign`; CMake; round 3 needs no GMP |

## Adding a new algorithm

1. Drop the source tree under `reference/<NEW_ALGO>/`.
2. Find each variant's `api.h` directory.
3. Add an entry to `algos.json`:
   ```json
   "NEW_ALGO": {
       "download_hint": "https://...",
       "root_dir": "NEW_ALGO",
       "variants": [
           { "name": "NEW_ALGO-L1", "dir": "Reference_Implementation/level1",
             "extra_cflags": [], "extra_ldflags": ["-lm"] }
       ]
   }
   ```
4. Run `python run_reference_benchmarks.py --probe-only --algos NEW_ALGO` to
   sanity-check the build.

If the algorithm needs OpenSSL, set `extra_ldflags: ["-lcrypto"]` and
ensure `cc` can find the headers (`-I/opt/homebrew/opt/openssl@3/include`).

## Common build failures

| Symptom | Fix |
|---|---|
| `fatal error: 'api.h' file not found` | The `dir` in `algos.json` is wrong — `api.h` must be directly in that directory |
| `undefined symbol: AES_set_encrypt_key` | Add `-lcrypto` to `extra_ldflags` |
| `fatal error: 'openssl/evp.h' file not found` (macOS) | `brew install openssl@3` and export `CPATH=$(brew --prefix openssl@3)/include`, `LIBRARY_PATH=$(brew --prefix openssl@3)/lib` (the run-all script does this) |
| `clock_gettime` undefined on Linux | Add `-lrt` to `extra_ldflags` (macOS has it in libc, Linux needs explicit link) |
| `undefined reference to 'randombytes'` | Most NIST refs ship `rng.c` in a sibling dir; list it in `extra_sources` |
| Variant built but produces wrong sig sizes | Wrong parameter set selected by `#define` in api.h — check the variant subdir matches the level you want |
| FAEST numbers ~50x too slow | Built without `HAVE_OPENSSL` (pure-C AES fallback) — install OpenSSL dev headers and rebuild |
| SQIsign bench dies with SIGILL on Pi | Default build reads `PMCCNTR_EL0`; rebuild with `-DNO_CYCLE_COUNTER` (the Pi script does) |
| SQIsign rows look 1000x off | Output unit mismatch — `(megacycles)` needs `--cpu-mhz`; `(milliseconds)` (NO_CYCLE_COUNTER build) needs no flag; the parser auto-detects from the captured file, so don't mix files |
| `openssl_sig_speed` prints cycles=0 | Linux: `sudo sysctl kernel.perf_event_paranoid=1` (containers never expose perf). macOS: run with `sudo` (kperf is a private API and needs root). Timings stay valid |
| `cp ... Resource deadlock avoided` (this repo on a Mac) | iCloud cloud-only placeholder file — open the folder in Finder and "Download Now", or work from a non-iCloud checkout |
| `[-] EC:P-256: N/N verifies FAILED` from openssl_sig_speed | Should not happen since the June 2026 fix (sign loop used to clobber the verify signature buffer); if it does, the verify timings for that algo are invalid — investigate before using them |

## Comparing reference numbers to liboqs

Both land in `../results/stage1_customer_form_<tag>.csv`, one row per algorithm and library (`Library`
column). For an algorithm in both (e.g. MAYO), the reference and liboqs rows should agree within the
libraries' optimisation differences; for one only here (HAWK, SQIsign, ...), the reference row is the only
number.
