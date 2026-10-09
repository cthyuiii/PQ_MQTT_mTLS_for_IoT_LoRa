# IoT-PQC — findings

What the benches in [README.md](../README.md) measured: one numbered finding per result, then the sources and the
work left for later. README.md covers how the code works and how to run it.

## Findings so far

Each finding says **where** it ran, **what** was tested, and **which library and version**. Numbers in
square brackets point to the [sources](#sources) at the end of this section; findings without one are
our own measurements, and the output file named in README section 0.2 is the evidence.

**Platforms**

| Tag | Hardware and software | Status |
|---|---|---|
| **[Mac]** | Apple M1 Pro, macOS 26.6, Apple clang 21 | full run `./run_all.sh --no-deps` on 28 Sep 2026: `results/*_mac.*`, log `results/run_mac.log`, versions `results/versions_mac.json` (the full version table is in [how_it_works.md](how_it_works.md)) |
| **[Pi-June]** | an earlier Pi 4 run, versions not recorded | its result files were removed on 29 Sep as older than two weeks (finding 73) |
| **[Pico-build]** | compiled for Pico W / Pico 2 W with arduino-pico 6.1.1 (GCC 16.1.0) | not run on a board |
| **[Pico]** | Pico W (RP2040, 200 MHz), arduino-pico 6.1.1, on the Mac's USB and the same Wi-Fi | runs of 28–29 Sep: `pico/logs/`, `results/*_pico_rp2040.*` |

**Which versions the numbers come from.** The [Mac] findings 1–34 were measured before the 28 Sep
update:
- OpenSSL 3.6.4;
- oqs-provider `8b87173` with **liboqs 0.15.0** inside (OpenSSL's Falcon, MAYO, SNOVA);
- **liboqs 0.16.0** for the `liboqs` stage;
- wolfSSL 5.9.2;
- Python 3.9.6, with pqcrypto 0.4.0 and cryptography 48.0.0 (bundling OpenSSL 4.0.0);
- Mosquitto 2.1.2.

The pinned versions (README section 0) replace them in the next run. [Pico-build] sizes are from arduino-pico 6.1.1
unless a finding says otherwise. Findings 44–47 used the pinned versions. Their round 3 rows add
oqs-provider `36cafae` on liboqs `b196b57a`, and their round 2 rows come from the pinned `c174ed7` build,
measured on the same day.

The same algorithm can come from different code in different libraries:
- OpenSSL has its own ML-DSA, SLH-DSA and ML-KEM.
- oqs-provider brings in liboqs's Falcon, MAYO and SNOVA.
- The `liboqs` stage calls liboqs directly.
- wolfSSL uses its own code.

**Stage 1: signature speed**

1. [Mac] SLH-DSA-SHA2-128s sign, OpenSSL 3.6.4 (native, `openssl_sig_speed`): 200 ms median. OpenSSL
   implements SLH-DSA itself since 3.5 [12, 19].
2. [Mac] Sign and verify through three libraries [17, 18, 19, 20]:

   | Median | liboqs 0.16.0 (direct) | OpenSSL 3.6.4 | wolfSSL 5.9.2 |
   |---|---|---|---|
   | ML-DSA-44 keygen / sign / verify | 30 / 57 / 27 µs | 67 / 283 / 73 µs (native EVP) | 30 / 120 / 36 µs |
   | Falcon-512 sign / verify | 153 / 25 µs | 368 / 220 µs (via oqs-provider 0.12.0-dev / liboqs 0.15.0) | — |
   | SLH-DSA-SHA2-128f sign | 20.9 ms | 9.4 ms | — |
   | SLH-DSA-SHA2-128s sign | 437 ms | 200 ms | 158 ms |

   - The two ML-DSA figures are different implementations (liboqs's vs OpenSSL's own).
   - Falcon is liboqs code on both sides, so most of that gap is the per-call
     `EVP_DigestSign/VerifyInit_ex` setup that the OpenSSL bench times on every call.
   - Two fixes made these runs possible. liboqs 0.16.0 removed SPHINCS+ (SLH-DSA replaces it), so the
     bench's SPHINCS+ names had been skipped silently [17]. The macOS Cython module also didn't load a non-Homebrew liboqs.
   - The wolfSSL figures are from wolfSSL's own benchmark with ARM assembly on (mean per op).
     - The first Pi wolfSSL build had left out SHA2 SLH-DSA; that's fixed.
     - The 28 Sep full run initially had no wolfSSL signature rows (finding 33); the wolfSSL stage was
       re-run the same night.
   - SLH-DSA's cost differs 2–3× between libraries for the same parameter set: it's all hashing, and
     the libraries' SHA-256 code differs.
3. *Removed 29 Sep (finding 73):* June Pi Stage 1 numbers, older than two weeks. Stage 1 on a Pi needs a
   new run.

**TLS 1.3 / mTLS key-exchange sweep** (`tls` stage: MQTT connections through the broker on another machine; no
run yet)

4. *Removed 29 Sep (findings 73, 76).*
5. *Removed 29 Sep (findings 73, 76).* The client's key share is 1,216 B by construction (ML-KEM-768
   encapsulation key 1,184 B + X25519 32 B) [10, 13]; the Pico rows in finding 71 carry measured handshake bytes.

**Payload protection: LoRaWAN, AES, Ascon** (measured only through the MQTT broker: the `pipeline` stage and the
Pico W's pipeline; no run of the new form yet)

6.–10. *Removed 29 Sep (finding 76):* the per-message, OTAA-join and wolfCrypt 64 B timings, and the Pico
   `aead_bench` build. All were measured on one device, not through a broker.

**MQTT over TLS / mTLS (Stage 2) and the full pipeline**

11. *Removed (findings 73, 76):* measured with the client and the broker on one Mac.
12. [Mac] OpenSSL 3.6.4's TLS refuses SLH-DSA certificates (`unknown certificate type`), so SLH-DSA
    is Stage 1 only. The wolfSSL 5.9.2 client can't load Falcon (5.9.4's native Falcon fixes that: finding 51), MAYO
    or SNOVA certificates [20]. Each failure is a row with its reason.
13.–16. *Removed (findings 73, 76):* measured with the client and the broker on one Mac (13–15), or by the retired
    Python telemetry stage (16). The Pico W's broker runs show the same session-ticket effect: after an mTLS
    handshake the broker sends 1,400 B (ECDSA-P256) or 8,568 B (ML-DSA-44), against 568 B after server-auth TLS
    (finding 71).

**Pico / constrained hardware**

17. The per-algorithm Pico sketches run unoptimised reference code (PQClean `clean`, mldsa-native
    `ref`, the NIST submission code) [22, 23], so their numbers are an upper bound. A published PQClean result
    on RP2040 at 133 MHz, for comparison: ML-DSA-44 signs in 158.9 ms and verifies in 44.0 ms, with a
    50.6 KB peak stack [16]. The alternatives checked: pqm4 is Cortex-M4 assembler with no RP2350 port [24];
    Mbed TLS / TF-PSA-Crypto has ML-DSA-87 only [25].
18. [Pico-build] liboqs 0.16.0 bare-metal (`OQS_EMBEDDED_BUILD`, arduino-pico 6.1.1) [17, 30] builds every
    tested algorithm. That includes SNOVA-24-5-4 on RP2040 (a 159.8 KB image), which the customer had
    reported as "no firmware image". ML-DSA-44 is 121.7 KB. With core 5.6.0 these were 163 KB and
    125 KB.
19. [Pico-build] wolfSSL 5.9.4 `wolfssl_bench` images are 70–116 KB with core 6.1.1 (5.9.2 on 5.6.0:
    84–125 KB) [20]. wolfSSL's `wc_slhdsa.h` still has no `extern "C"` guard in 5.9.4 (an upstream bug),
    worked around in the sketch.
20. [Pico-build] ascon-c 446347f [9]: the inline-assembly `armv6m` build doesn't compile for RP2040. The
    standalone-assembly `armv6m_lowsize` build does, and is the one used.
21. From the picow notes (PQClean and submission code on the boards):
    - MAYO-3 needs a 504 KB verify stack, so it can't fit.
    - SDitH2 doesn't compile on 32-bit chips.
    - SDitH-cat3 and FAEST-128f fault from long compute times, not from memory.
22. The committed Pico `results.csv` had only 3 rows because every run overwrote it; it now merges.

**Optimising the Pico code** (details: [how_it_works.md part 4](how_it_works.md#4-optimising-the-pico-code))

23. [Pico-build] The arduino-pico defaults (5.6.0 and 6.1.1 alike) are a 200 MHz RP2040 and a 150 MHz RP2350, with
    sketches at `-Os` [30]. The RP2040 study in 17 ran at 133 MHz [16], so compare against it with
    `--freq 133`. liboqs itself is built at `-O3`: CMake appends it after the script's `-Os`.
24. [QEMU] liboqs 0.16.0 for the Pico, with its portable 64-bit Keccak replaced by XKCP's hand-written
    assembler [27] (`--keccak xkcp`). Instructions per operation, from QEMU 11.1.1 on the Mac: the M0+
    code runs on `mps2-an385`, the M33 code on `mps2-an505`. Every signature is identical to the
    stock build, and the SHA-3 known answers pass. Re-measured after the arduino-pico 6.1.1 / GCC 16.1.0
    update:

    | Algorithm | RP2040 (ARMv6-M asm): keygen / sign / verify | RP2350 (ARMv7-M asm): keygen / sign / verify |
    |---|---|---|
    | Keccak alone (SHAKE256, 1 KB in and out) | 1.39× | 1.48× |
    | ML-DSA-44 | 1.20× / 1.10× / 1.16× | 1.35× / 1.24× / 1.31× |
    | ML-DSA-65 | 1.21× / 1.06× / 1.17× | 1.36× / 1.19× / 1.33× |
    | SLH-DSA-SHAKE-128f | 1.18× | 1.30× |
    | Falcon-512, MAYO-1, SNOVA-24-5-4, SLH-DSA-SHA2-128f | 1.00–1.07× (Keccak isn't their hot spot) | 1.00–1.10× |

    - GCC 16.1 compiles the *stock* M0+ Keccak about 9% leaner than GCC 14.3 did (299,640 against
      327,400 instructions for the same SHAKE256 job), so the assembler's lead there shrank from 1.51×
      to 1.39×.
    - liboqs's SLH-DSA carries its own Keccak (slh-dsa-c `keccak_f1600`), so the swap replaces that too.
    - XKCP's portable 32-bit C variant is slower on both chips (0.79–1.00×).
    - These are instructions, not cycles: QEMU doesn't model the M0+'s 2-cycle loads and branches or
      the Pico's flash cache. The board run gives the time.
25. [Pico-build] With XKCP, the ML-DSA-44 `liboqs_bench` firmware *shrinks*: 121,672 → 89,136 B on
    RP2040, and 116,740 → 86,236 B on RP2350 (core 6.1.1). The stock Keccak is fully unrolled at `-O3`.
26. [QEMU] With the same liboqs code, the M33 needs 2–5× fewer instructions than the M0+ (GCC 16.1).
    For example, ML-DSA-44 signing takes 2.32 M instructions against 6.80 M, and Falcon-512 keygen 88 M
    against 376 M: the M0+ has no 32×32→64-bit multiply [28, 29]. So the RP2350's lead over the RP2040
    is more than its clock.
27. [Pico-build] `--opt` takes the family sketches from `-Os` to `-O2` or `-O3`. The ML-DSA-44 sketch
    on RP2040 (core 6.1.1) grows from 71,176 B to 75,072 B (`-O2`) and 76,784 B (`-O3`); the speed
    needs a board.

**Repository**

28. 1,774 identical iCloud duplicates were tracked on `picow`; they're ignored here. A demo private
    signing key (`experiments/server_identity.sk`) had been committed since `88d0ae19`; it's untracked
    now, but treat it as public.
29. The 27 per-parameter-set Pico folders are now 7 family folders: 913 files (7.0 MB) became 370
    (3.0 MB). Each variant's code is kept verbatim, and flash and RAM are identical to the old folders
    for all 27 variants on both boards.
30. The 794 staged files are the Pico sketches' vendored C sources plus the new host files; a
    microcontroller has no shared libraries, so each sketch carries its code. 6.1 MB of the 12.6 MB
    are three baked UOV key headers in `uov1_bench/src/`.
31. Stock macOS bash 3.2 aborted `run_all.sh` on an empty array under `set -u`; fixed.
32. [Mac] `./run_all.sh --quick --no-deps` ran every non-reference stage in 5 min 30 s on the M1 Pro
    (after the one-off builds), exit 0:
    - 138 Stage 1 rows, all OK;
    - Stage 2: 89 rows;
    - pipeline: 78 rows.

    Every failure row is one of the known cases in 12.
33. [Mac] The first full run (28 Sep, 01:50–02:10, about 20 min) exposed a bug that the quick run had
    hidden.
    - wolfSSL's benchmark spells SHAKE sets `-slhdsa-shake128f` but SHA2 sets `-slhdsa-sha2-128f`.
      `run_all.sh` used the SHA2 spelling for both, so the benchmark printed its usage and measured no
      signatures. The stage still reported "wrote".
    - Fixed: the names are corrected, and a failed benchmark now prints `[!]`. The re-run wolfSSL stage
      took 2 min and the Stage 1 table went from 138 to 156 rows, all OK.
    - The OpenSSL stage now prints one progress line per algorithm; before, it showed nothing for
      several minutes.
34. [Mac] Without `--no-deps`, the dependency step used plain `brew install`, which upgrades outdated
    formulae ("Unless $HOMEBREW_NO_INSTALL_UPGRADE is set, brew install formula will upgrade formula if
    it is already installed but outdated", `man brew`). On 28 Sep, automake, libtool and liboqs were
    outdated on this Mac. The step now installs missing packages only (Homebrew
    `HOMEBREW_NO_INSTALL_UPGRADE=1`, apt `--no-upgrade`).
35. [Mac] Dependency update and pin, 28 Sep. **The Mac results above predate it; re-run to refresh them.**

    | Component | Before | After |
    |---|---|---|
    | wolfSSL | 5.9.2 | 5.9.4 |
    | oqs-provider | `8b87173` with liboqs 0.15.0 | `c174ed7` with liboqs 0.16.0 |
    | arduino-pico core | 5.6.0 (GCC 14.3) | 6.1.1 (GCC 16.1.0, Pico SDK 2.3) |
    | Python | 3.9.6 (Xcode) | 3.14.7 (Homebrew) |
    | cryptography | 48.0.0 | 50.0.1 |
    | Cython | 3.2.4 | 3.3.0, plus setuptools 84.0.0 (Python 3.12+ venvs lack it) |
    | Homebrew automake / libtool / liboqs | older | 1.19 / 2.6.2 / 0.16.0 |

    - oqs-provider `c174ed7` includes this summer's security fixes, and now uses the same liboqs as the
      Cython stage and the Pico. Its next upstream commit moves MAYO / SNOVA to round 3, which needs
      unreleased liboqs, so it's skipped.
    - All certificates were regenerated (20 complete sets).
    - pqcrypto stays on 0.4.0: 1.0.0 dropped Falcon and renamed its API.
    - The old venv (Python 3.9.6, which reached end of life in Oct 2025) had been corrupted inside
      iCloud Drive: two packages had lost their metadata, and two cryptography versions were
      half-installed. It is rebuilt as `.venv.nosync`, which iCloud skips, with `.venv` linking to it.
36. [Pico-build] The wolfSSL warning "For timing resistance / side-channel attack prevention consider
    using harden options" (148 per build) came from wolfSSL's own `settings.h`.
    - It defines `HAVE_ECC` for every Arduino build, while our settings only turned on ECC's timing
      resistance in the ECDSA build.
    - Fixed: `TFM_TIMING_RESISTANT`, `ECC_TIMING_RESISTANT` and `WC_RSA_BLINDING` are now always on, as
      in the Mac / Pi `./configure` build.
    - A compile of every Pico sketch on the new core shows 0 of these warnings.
37. [Pico-build] Every runner entry (166 board × sketch × variant builds) compiled with arduino-pico
    6.1.1: 164 OK. The two failures are real: QR-UOV-q31-L3 and -q31-L10 need about 350 KB and 276 KB
    of static RAM on the RP2040 (`sign.c` keeps two static 72 KB tables next to the 180 KB big stack).
    They could never fit its 264 KB, and are now RP2350-only with that reason. The QEMU Keccak check
    passes on the new toolchain (finding 24).
38. [Pico] The 28 Sep Pico W run stopped at its first sketch with `UPLOAD_FAIL`. The reason wasn't
    kept; `results.csv` now records it (e.g. "UPLOAD_FAIL: /Volumes/RPI-RP2 did not mount").
39. [Mac] `run_all.sh` now watches by default. In the quick run after the update, independent
    subscribers received 5,280 of 5,280 pipeline messages.
40. [Mac] `collate_results.py` puts every result file into `results/all_results.csv`, one row per
    number (10,787 rows from 14 files on 28 Sep). `run_all.sh` and the Pico runner call it at the end.
41. [Mac] `build_wolfssl.sh` only cloned wolfSSL when its cache folder was missing, so a new version
    tag would have rebuilt the old source under the new label. It now switches the checkout.
42. [Mac] A `git pull` in `oqs-provider/` (28 Sep, 03:25) moved the source to `36cafae`: round-3 MAYO /
    MQOM / SNOVA.
    - That commit removes every round-2 SNOVA name we use (`snova2454`, `snova2455`, `snova2965`, …)
      in favour of `snova1b`…`snova5s`, replaces `mqom2…` with `mqom3…`, and moves MAYO to round-3
      parameters.
    - Against liboqs 0.16.0 it fails to build (180 errors, e.g. `OQS_SIG_alg_snova_SNOVA_I_B`
      undeclared).
    - The provider OpenSSL loaded was still the `c174ed7` build, so no result was affected. The clone
      is back on `c174ed7`.
    - `./run_all.sh --dry-run` now flags an oqs-provider source that doesn't match its build.
43. [Mac] `pico/tests/aead_host_test` cached BearSSL once, so after the core update it would have tested
    core 5.6.0's BearSSL against 6.1.1's headers. The cache is now per core version; the test passes on
    6.1.1's BearSSL.

**Round 3 MAYO / SNOVA / MQOM, and a broker on another machine**

44. [Mac] The newer oqs-provider is usable now, **beside** the pinned pair rather than instead of it
    [32–35].
    - Build: oqs-provider `36cafae` against liboqs main `b196b57a` (`0.16.0-50`) builds without errors.
      The `round3` stage does this in about 1 minute.
    - All 16 round 3 sets keygen, sign and verify through OpenSSL 3.6.4 EVP: MAYO-1/2/3/5, SNOVA I / III / V
      × b / k / s, and MQOM v3 cat 1 / 3 / 5 (GF(16), fast, constant time).
    - The pinned `c174ed7` build still serves every other stage.
    - What can't follow yet: the Pico, whose liboqs is the 0.16.0 release (`make_liboqs_lib.sh`), and the
      liboqs stage. Both measure the same liboqs code as the OpenSSL route, so the round 3
      numbers for them wait for the next liboqs release.
45. [Mac] Round 2 → round 3, OpenSSL 3.6.4 + oqs-provider (`c174ed7` on liboqs 0.16.0 → `36cafae` on
    liboqs `b196b57a`). Each timing is the median of 200 runs, keygen / sign / verify in ms.

    | Set | Round 2: ms | Round 2: pk / sig B | Round 3: ms | Round 3: pk / sig B |
    |---|---|---|---|---|
    | MAYO-1 | 0.197 / 0.346 / 0.261 | 1420 / 454 | 0.206 / 0.339 / 0.279 | 1456 / 464 |
    | MAYO-2 | 0.194 / 0.303 / 0.229 | 4912 / 186 | 0.200 / 0.288 / 0.256 | **2928** / 239 |
    | MAYO-3 | 0.275 / 0.551 / 0.359 | 2986 / 681 | 0.273 / 0.501 / 0.365 | 2986 / 681 |
    | MAYO-5 | 0.440 / 0.936 / 0.516 | 5554 / 964 | 0.428 / 0.777 / 0.516 | 5554 / 964 |
    | SNOVA level I | 24-5-4: 0.220 / 0.602 / 0.386 | 1016 / 248 | I_S: 0.356 / 0.528 / 0.345 | 1016 / 272 |
    | | | | I_B: 0.321 / 0.575 / 0.401 | 656 / 388 |
    | | | | I_K: 0.308 / 0.617 / 0.420 | **376** / 528 |
    | MQOM cat 1 | v2 `fastr5`: 0.602 / 1.252 / 1.109 | 60 / 3280 | v3 `fastct`: 0.213 / 0.801 / 0.756 | 64 / 3316 |
    | MQOM cat 3 | 2.011 / 13.047 / 5.218 | 90 / 7738 | 0.352 / 2.300 / 2.130 | 96 / 7564 |
    | MQOM cat 5 | 4.566 / 25.098 / 14.608 | 122 / 13772 | 0.450 / 4.170 / 3.945 | 128 / 13540 |

    - **MAYO-2's public key shrinks 40%** (4912 → 2928 B), and its signature grows 186 → 239 B.
      MAYO-1 grows slightly. MAYO-3 and MAYO-5 keep their sizes and sign 9% and 17% faster.
    - **MQOM v3 signs 1.6× (cat 1), 5.7× (cat 3) and 6.0× (cat 5) faster than v2.** Signatures are
      within 3%; public keys grow by 4 B. (v2's `r5` and v3's `ct` are each the variant the provider enables.)
    - **Round 3 SNOVA replaces the round 2 shapes with three per level**: b(alanced), k(ey), s(ignature).
      At level I, SNOVA_I_K has the smallest public key of any multivariate set here (376 B, signature
      528 B). SNOVA_I_S keeps 24-5-4's 1016 B public key with a 24 B longer signature.
46. [Mac] The round 3 certificates run over Stage 2. Setup: Mosquitto 2.1.2, OpenSSL 3.6.4 client,
    X25519MLKEM768, `--quick` run.
    - All 13 (4 MAYO, 9 SNOVA) load in the broker and complete TLS and mTLS.
    - The quick run's times aren't for reporting. Handshake bytes are deterministic, so they are.
    - Server → client under TLS, round 2 → round 3: MAYO-2 12,294 → 8,485 B (−31%); MAYO-1
      6,116 → 6,218 B.
    - SNOVA level I: round 2 24-5-4 4,700 B; round 3 I_K 4,256 B, I_B 4,396 B, I_S 4,768 B.
    - The ClientHello is 16 B longer (1,559 → 1,575 B) with the round 3 provider loaded. That is its
      longer signature-algorithm list.
47. [Mac] `--serve-broker` and `--broker IP` work end to end. Test: one Mac as both ends through its LAN
    address 192.168.50.131, `--quick`.
    - `mtls`, `pipeline`, `mqtt` telemetry and `round3`'s Stage 2 all completed against the served
      brokers. The pipeline watchers received 5,280 of 5,280 messages.
    - Each meta file records `broker: 192.168.50.131:18830`.
    - The dry-run certificate check passes with the broker's CA. It fails (exit 1) when `certs/` holds a
      different CA, which is the case it exists to catch.
    - The served SLH-DSA listeners fail as in item 12.
    - The times are one machine talking to itself, not a network. A Mac ↔ Pi run gives the first LAN
      numbers.

**Standardising on C, and what the Stage 2 failures are** (28 Sep, after the second full Mac run)

49. [Mac] Every stage `run_all.sh` counts now times C code.
    - The `liboqs` stage replaces the Cython driver with `sig_speed.c` built on liboqs
      (`-DSIG_LIBOQS`). It uses the same message, loops, statistics and output as the OpenSSL bench.
    - Against the Cython driver the same day, on the same liboqs 0.16.0, C / Cython is 1.04 at the median
      over 195 operations (range 0.90–1.33). The Cython driver already timed the C call itself
      (`clock_gettime` around it, no Python in between). So the change removes a Python / Cython toolchain,
      not a bias.
    - The Python-timed `mqtt` telemetry stage is retired from `run_all.sh`; `pipeline` covers that path in
      C.
50. [Mac] Why liboqs is often faster than OpenSSL. Same machine, same day, median of 200:

    | Operation | liboqs 0.16.0, direct | OpenSSL 3.6.4 | Why |
    |---|---|---|---|
    | Falcon-512 verify | 24 µs | 231 µs | Same liboqs code, reached through oqs-provider. `EVP_DigestVerifyInit_ex` costs 217 µs per call in the provider; the verify itself costs 25.6 µs |
    | ML-DSA-44 sign / verify | 66.5 / 28 µs | 288.5 / 75 µs | Different code. OpenSSL has its own ML-DSA (setup only 1.2 µs); liboqs's has an AArch64 backend (`OQS_ENABLE_SIG_ml_dsa_44_aarch64`) |
    | SLH-DSA-SHA2-128f sign | 21.0 ms | 9.7 ms | Reversed. liboqs's SLH-DSA carries its own portable SHA-256 (`slh_dsa_c/sha2_256.c`), while OpenSSL's uses the CPU's SHA-256 instructions |

    Since finding 55 the OpenSSL bench times that setup separately, so its sign / verify rows count the
    operation only.
51. [Mac] Stage 2 certificate failures: causes and fixes.
    - **wolfSSL client with Falcon: fixed.**
      - wolfSSL 5.9.4 has native Falcon (`--enable-falcon`, experimental) on oqs-provider's TLS codepoints
        (0xFED7 for Falcon-512). `build_wolfssl.sh` now enables it with native double precision.
      - Falcon-512 and -1024 certificates complete TLS and mTLS with the wolfSSL client. That was a local
        smoke test, so it isn't counted.
      - wolfCrypt signs Falcon-512 in 0.187 ms and verifies in 0.019 ms. Its default emulated-float build
        signs in 3.06 ms.
      - Its benchmark has no Falcon keygen, so those Stage 1 rows are `PARTIAL`.
      - The double-precision build needs `ac_cv_vcs_checkout=no`: 5.9.4's Falcon code leaves unused
        helpers, which a git checkout's `-Werror` rejects.
    - **wolfSSL client with MAYO or SNOVA: not fixable.** wolfSSL has no implementation. (SNOVA since: finding 106.)
    - **SLH-DSA in TLS: not fixable on the pinned stack.**
      - oqs-provider has SLH-DSA with TLS codepoints 0x0911–0x091C [36]; wolfSSL 5.9.4 uses the same ones.
      - But with OpenSSL 3.5 or newer, oqs-provider switches its own ML-DSA and SLH-DSA off at startup
        (`oqsprov.c`) in favour of OpenSSL's.
      - OpenSSL 3.6.4's SLH-DSA has no TLS codepoint: `openssl list -tls-signature-algorithms` lists none.
      - Re-enabling the provider's would be an experimental patch, with two providers claiming the same
        OIDs.
52. [Mac] SLH-DSA-SHA2-128s really does take 200 ms to sign.
    - OpenSSL 3.6.4: median of 20, std 8.8 ms. wolfSSL: 158 ms. liboqs: 451 ms.
    - FIPS 205's "s" sets trade signing time for size [12]. One signature computes 7 hypertree layers of
      512 WOTS+ keys (35 chains of 15 hashes each), plus 14 FORS trees of 4,096 leaves. That is about
      2.2 million hash calls, roughly 91 ns each here.
    - SLH-DSA-SHA2-128f signs in 9.5 ms, with a 17,088 B signature instead of 7,856 B.
53. [Mac] MQTT results count only between two machines (28 Sep).
    - Without `--broker`, `run_all.sh` skips `mtls`, `pipeline` and `round3`'s Stage 2.
    - `collate_results.py` leaves out any run whose broker was on the same machine (meta `broker_local`).
    - So the 04:40 full run's `mqtt_mtls_summary_mac`, `mqtt_mtls_summary_mac_r3` and
      `pipeline_summary_mac` aren't counted. Their byte counts stand; their times need the Mac ↔ Pi run.

54. [Mac] The AEAD benches no longer repeat a counter under one key.
    - Before, `aead_speed` pushed 51,200 frames per size through one key with a 16-bit FCnt. The counter
      wrapped across sizes, so GCM and Ascon nonces repeated.
    - The pipeline restarted FCnt at 1 on every connection under the same key.
    - The data was synthetic and no timing or byte count depended on it. But this is the textbook GCM
      misuse: it leaks the XOR of plaintexts and GCM's authentication key.
    - Now `aead_speed` uses fresh keys per size and refuses more than 65,535 frames per key, and the
      pipeline's FCnt runs on across connections.
    - Each pipeline process has its own DevAddr, which the receiver reads from the frame as a network
      server does.
    - The frame layout is unchanged, so Pico ↔ OpenSSL byte equality and earlier results stand.
    - Checked: the `app_aead` self-test passes, and the watchers verified 3,240 of 3,240 pipeline frames.

**One timing method and full statistics** (28 Sep)

55. [Mac] Stage 1 times only the operation, in every library.
    - OpenSSL's per-call `EVP_DigestSign/VerifyInit_ex` is timed separately (`sign_setup` / `verify_setup`
      rows in `openssl_sig_speed_<tag>.csv`). It's kept because every TLS handshake pays it.
    - With that out, OpenSSL + oqs-provider matches liboqs exactly: Falcon-512 sign 154.5 / verify 24 µs,
      against 154 / 24 µs direct. The setup it pays per call is 207 µs.
    - ML-DSA-44 is still 283.5 against 67.5 µs. Its setup is only 1 µs, so that gap is OpenSSL's slower ML-DSA
      code (finding 50).
56. [Mac] Every Stage 1 algorithm and library runs the same number of iterations: `SIG_N`, default 100.
    - That covers OpenSSL, liboqs, wolfSSL, the `bench_template.c` reference sets (no more adaptive counts),
      and MQOM and SQIsign's own benches.
    - Before, fast sets had 200 and SLH-DSA "s" sets 20.
    - HAWK's own bench is time-based and can't take a count.
    - The Pico keeps its per-sketch counts (your choice); every Pico row records its n.
57. [Mac] Statistics per run:
    - **Stage 1** (OpenSSL, liboqs, wolfSSL, `bench_template.c` references): mean, median, std, min, max,
      ops/s, cycles and sizes, all in the Stage 1 table (new `min_us` / `max_us` columns).
    - **Gaps:** MQOM, SQIsign and HAWK print means only from their own tools. wolfCrypt's benchmark (kept only
      for ML-KEM / X25519 and AEAD throughput) prints mean and ops/s.
58. [Mac] wolfSSL signatures now go through the same C bench, which exposed two unfair settings.
    - `wc_SignatureGenerate` verifies every signature after signing. With `_ex(verify = 0)`, as EVP does,
      ECDSA-P256 sign drops from 620 to 388 µs.
    - The build lacked wolfSSL's ARM64 P-256 / RSA code. With `--enable-sp --enable-sp-asm`, ECDSA-P256 signs in
      17.5 µs (OpenSSL: 18) and RSA-2048 in 0.56 ms instead of 1.72 ms.
    - Falcon keygen is measured now: 4.9 ms.
    - ML-DSA's private key is reported at its FIPS 204 size, 2,560 B; wolfSSL's own length adds the public
      key.
59. [Mac] Every TLS / mTLS run now reports the full set.
    - **Times:** mean, median, std, min, max; the `tls` stage adds p90, p99 and handshakes/s.
    - **Bytes:** up (tx) and down (rx) for the handshake, the MQTT exchange and the whole connection, plus
      totals.
    - **Socket and TCP:** socket writes / reads, and the kernel's TCP segment counts.
    - **On-wire estimate:** bytes + 52 B of IPv4 + TCP headers per segment.
    - The pipeline adds mean / median / std / min / max for seal, open, broker round trip and end to end.
60. [Pico-build] `wolfssl_bench` compiles without the `-Wdeprecated-enum-float-conversion` warnings: `SAMPLES`
    / `BATCH` are now `int` constants.

61. [Repo] Cleanup (28 Sep).
    - **Removed:** `get-pip.py`; the Python prototype benches (`experiments/*.py` and the
      `network/benchmark_*.py` scripts other than the Stage 2 driver); the notebook;
      `run_openssl_speed_suite.sh`; 13 stale, gitignored sketch folders.
    - **Kept then:** the prototypes' CSVs; they were removed on 29 Sep (finding 73). Everything removed is in
      git history.
    - **Merged:** the RSA and ECDSA Pico sketches into `rsa_bench` / `ecdsa_bench`
      (`-DPICO_VARIANT_<set>`). Flash is unchanged, except RSA-2048 is +8 B because it now also checks that
      signing succeeded, as the 3072 / 4096 sketches did.
    - **Folded:** `tls_handshake_timer.c` into `mqtt_tls_timer`.
    - **Dependencies:** `requirements.txt` went from 10 packages to 1 (pyserial).

**29 Sep 2026**

62. [Repo] CROSS is dropped from every bench.
    - Code: `run_all.sh`, `gen_certs.sh`, the Stage 2 list, the Pico runner, the Pico liboqs build and the QEMU
      check.
    - Results: all writable result files, and `all_results.csv`.
    - The two read-only June Pi files that still held CROSS rows were removed on 29 Sep (finding 73), with
      the filter that skipped them.
63. [Pico] liboqs MAYO-2 hung the RP2040 with the default 160 KB stack. The entry now gets 224 KB, like MAYO-1.
64. [Pico] RSA-4096 key generation takes 2,927 s (49 min) on the RP2040 at 200 MHz. Its third run outlived
    the runner's one-hour silence limit, and the board dropped off USB, which failed every flash after it.
65. [Mac, Pico-build] The GCM / Ascon nonce is now DevAddr ‖ FCnt (all 32 bits) ‖ zeros on the host and on the
    Pico.
    - GCM used to keep only FCnt's low 16 bits. That was a layout left over from LoRaWAN's A-block;
      the 12-byte nonce has room for all 32, as Ascon had.
    - `wolfssl_bench` used a single incrementing nonce byte, which repeated every 256 messages under one
      key. It now uses a 32-bit counter.
    - Timings and frame sizes are unchanged. The Pico LoRaWAN frames still equal OpenSSL's; GCM and Ascon
      round-trip and reject tampering.
66. [Mac, Pico-build] Downlink frames next to uplinks: MHDR 0x60 and Dir = 1 in A_i, B0 and the GCM / Ascon nonce
    (DevAddr ‖ FCnt ‖ Dir ‖ zeros), so an uplink and a downlink with the same counter never share a keystream or
    nonce. A LoRaWAN 1.1 downlink MIC is one CMAC (SNwkSIntKey), where the uplink computes two. Since finding 76
    both directions run only through the broker (the pipeline); the local timings first recorded here were removed.
67. [Mac] How the downlink code was checked:
    - It matches ChirpStack's LoRaWAN 1.1 downlink MIC vector [6] (`77701EA3`), in the self-test on the
      host and in the Pico's known-answer check (`lora_aead.h`).
    - A copy with the Dir byte removed fails that self-test.
    - A 1.0.x downlink frame that the openssl CLI builds from the spec text (A_1, B0, CMAC) equals
      `app_seal`'s, byte for byte.
    - `pico/tests/aead_host_test` compares every scheme in both directions at 4 sizes: 48 frames since
      finding 76, each identical between the Pico code and the host code.
68. [Pico-build] `pico/sketches/mqtt_tls_bench` builds Stage 2 and the pipeline for the Pico W / Pico 2 W.
    - What it runs: wolfSSL 5.9.4 as a TLS 1.3 client (X25519MLKEM768 only), arduino-pico 6.1.1, over
      Wi-Fi, against `./run_all.sh --serve-broker`.
    - Same packets, CSV rows and summary code as the host client: 50 connections (+5 warm-up) per mode,
      then 3 pipeline connections × 200 messages per block (51 B; since finding 76, 6 schemes × up / down).
    - Firmware sizes (flash / RAM free for heap and stack):

      | Board | ECDSA-P256 | ML-DSA-44 |
      |---|---|---|
      | Pico W | 552 KB / 188 KB free | 572 KB / 188 KB free |
      | Pico 2 W | 541 KB / 449 KB free | 558 KB / 449 KB free |

    - Falcon-512 is included: wolfSSL's native Falcon with integer float emulation (neither chip has a
      double FPU) and small-memory signing. It is 586 KB, with 188 KB RAM free, on the Pico W, and 573 KB on
      the Pico 2 W. The Mac's wolfSSL client completes Falcon-512 TLS and mTLS with the same certificates
      (finding 51). The older "cannot load CA cert" rows predated that build (removed with the local runs,
      finding 73).
    - A hardware watchdog (8 s without progress) turns a hang into a reboot that the log reports as
      `#watchdog …`. Each row carries the free heap before its connection.
    - The runner writes each log line as it arrives. A block cut off by a hang, a reset or Ctrl-C keeps
      its rows, with the reason as its status.
    - The runner parse → summary → `all_results.csv` path is checked by `pico/tests/mqtt_parse_test.py`.
69. [Pico] First board run: Pico W (RP2040, 200 MHz), wolfSSL 5.9.4, ECDSA-P256 certificates,
    X25519MLKEM768, over Wi-Fi to the Mac's broker. Before the watchdog existed, the board hung with no
    output during the mTLS block, after 37 recorded connections (the plain and TLS blocks had finished).
    The rows were read off the terminal, because that runner only wrote its log at the end:

    | mTLS, n = 37 | median | mean | min | max |
    |---|---|---|---|---|
    | TCP connect | 10.6 ms | 14.2 ms | 8.4 ms | 26.4 ms |
    | TLS handshake | 1,278 ms | 1,299 ms | 1,273 ms | 1,388 ms |
    | MQTT CONNECT → CONNACK | 29.5 ms | 92.7 ms | 15.9 ms | 513 ms |
    | total | 1,378 ms | 1,406 ms | 1,301 ms | 1,801 ms |

    - The handshake moves 1,935 B up and 2,461 B down. MQTT receives 1,400 B: the 4-byte CONNACK plus
      the broker's TLS 1.3 session tickets.
    - The Pico's 1.28 s is almost all computation: the ML-KEM-768 + X25519 key exchange, the ECDSA verify and the ECDSA sign on a
      Cortex-M0+.
    - The CONNACK time varies 30× (16–513 ms), where the handshake varies under 10 %. The cause is not
      measured yet (Wi-Fi retransmissions are one candidate).
    - Cause of the hang: unknown. The next run's free-heap column shows whether memory runs out, and the
      watchdog reports a hang instead of going silent.

70. [Mac] The `tls` sweep runs between two machines, like Stage 2.
    - `tls_sweep.sh` connects to the broker machine's Stage 2 listeners (`--serve-broker`);
      `run_all.sh --broker IP --only tls` runs it. Since finding 76 each run is a full MQTT connection.
    - The broker's OpenSSL config now accepts the sweep's five groups (ML-KEM-512 / 768 / 1024,
      X25519MLKEM768, X25519). Stage 2 still always gets X25519MLKEM768, because every client offers only
      that group.
    - A failed combination is now a row with its reason (it used to be dropped).
    - Each run writes `tls_handshake_meta_<tag>.json`. `collate_results.py` counts a sweep only if its
      broker was another machine.
    - The broker must be restarted to pick up the five groups; an old broker answers only X25519MLKEM768,
      and the other four come back as failure rows with the reason.
71. [Pico] Second Pico W run (RP2040, 200 MHz; wolfSSL 5.9.4; X25519MLKEM768; Wi-Fi RSSI −28 to −33 dBm;
    broker on the Mac). Medians, 50 connections per row unless marked PARTIAL:

    | Certificate | Mode | TCP | TLS handshake | MQTT CONNECT → CONNACK | handshake up / down | wolfSSL peak heap |
    |---|---|---|---|---|---|---|
    | (plain reference) | plain | 14.0 ms | — | 12.6 ms | — | — |
    | ECDSA-P256 | TLS | 11.4 ms | 1,232 ms | 215 ms | 1,387 / 2,256 B | 20.4 KB |
    | ML-DSA-44 | TLS | 10.9 ms | 1,069 ms | 127 ms | 1,393 / 11,790 B | 32.1 KB |
    | Falcon-512 | TLS | 10.5 ms | 977 ms | 206 ms | 1,391 / 5,641 B | 22.0 KB |
    | ML-DSA-44 | mTLS (PARTIAL, 21) | 10.4 ms | 1,324 ms | 41.6 ms | 7,883 / 11,993 B | — |
    | Falcon-512 | mTLS (PARTIAL, 48) | 13.4 ms | 1,992 ms | 37.0 ms | 3,926 / 5,846 B | — |

    - **Server-auth TLS: the post-quantum certificates were faster than ECDSA-P256 on the Pico.** Falcon-512
      took 977 ms and ML-DSA-44 1,069 ms, against 1,232 ms for ECDSA-P256. The client only verifies, and
      ECDSA verification is the slow one on a Cortex-M0+.
    - **mTLS: Falcon-512 is the slowest (1,992 ms).** The client also signs, and wolfSSL's Falcon signing
      emulates floating point in software on this chip.
    - **mTLS hung in every mTLS block.** ECDSA-P256 hung during its warm-up; ML-DSA-44 after 21 connections,
      Falcon-512 after 48. No plain or TLS block hung.
      - The free heap stayed flat, so this is not a leak.
      - The watchdog fired, so the board was stuck outside the socket waits (which time out after 10 s).
      - Suspected then: the 8 KB stack overflowing while the client signs. Run 3 ruled this out (finding 72).
    - The MQTT CONNECT → CONNACK time was about 5× longer after server-auth TLS than after mTLS. The cause
      is not measured.
    - The mTLS rows were recovered from the line-by-line logs as `PARTIAL`: complete connections before the
      hang, with the reason as the status. The runner now summarises any cut-off block this way.
72. [Pico] Third Pico W run, same setup, with the painted stack and resume-after-watchdog. Every firmware
    reached `=== done`.
    - **The stack is not the cause.** The peak was 1.5–2.8 KB in every block, far under the core's 8 KB. The
      sketch now uses a 16 KB painted stack, only to keep measuring the peak.
    - **The hangs are not mTLS-specific.** This run hung in:
      - ML-DSA-44 `connect TLS` (after 14 connections) and `connect mTLS` (after 32);
      - Falcon-512 `connect mTLS` (after 27);
      - ECDSA-P256 `pipeline TLS` (during its first connection).

      ECDSA-P256 `connect mTLS` completed all 50. About 1 connection in 25–50 hangs, in any mode that
      uses TLS.
    - **Where it hangs is recorded from now on.** The sketch keeps the step in progress in a watchdog
      scratch register: TCP connect, TLS handshake, MQTT CONNECT, SUBSCRIBE, PUBLISH / echo, TLS close,
      TCP close or serial output. After the reboot it reports `#watchdog <block>: hung during <step>
      (connection n)`, and the step ends up in the row's status.
    - Stage 2, medians (n = 50 unless PARTIAL):

      | Certificate | TLS | mTLS |
      |---|---|---|
      | ECDSA-P256 | 1,229 ms | 1,290 ms |
      | ML-DSA-44 | 1,091 ms (PARTIAL, 14) | 1,293 ms (PARTIAL, 32) |
      | Falcon-512 | 978 ms | 1,996 ms (PARTIAL, 27) |

    - Pipeline, 3 connections × 200 messages of 51 B each: the median round trip through the broker is
      10.1–10.4 ms over TLS or mTLS, and 8.3 ms over plain MQTT.
    - wolfSSL's peak heap in the mTLS pipeline: Falcon-512 75.9 KB (its signing), ML-DSA-44 39.0 KB,
      ECDSA-P256 21.0 KB. All three fit the RP2040's 264 KB.
73. [Repo] Results older than two weeks, or measured on one machine, were removed on 29 Sep. The user asked
    for this, and also that key exchange count only between two machines.
    - **Moved out of the repo:** 58 files and folders plus 3 Pico rows, to
      `~/IoT-PQC-removed-2026-09-29/` with the same paths. Delete that folder to drop them for good. They
      were:
      - **Older than two weeks:** the June Pi files (Stage 1 suite, handshake sweep, handshake bytes); the
        June Mac `openssl speed` suite; the April–June Python prototype CSVs (`results/` kems, e2e,
        bytes_wire, cpu_memory, tls_handshake_*, tls_bytes; `experiments/results/`;
        `network/results/`); the Cython CSVs; 7 June Pico logs; the 3 June RP2350 FAEST rows.
      - **Measured on one machine:** the Mac's Stage 2, pipeline and round 3 Stage 2 runs with their
        watch logs, and the wolfCrypt key-exchange benchmark (ML-KEM /
        X25519 operations).
      - **No longer read by anything:** the `*_quick` smoke runs, the retired telemetry stage's files, and
        untagged legacy files.
    - **Key exchange:** the `wolfssl` stage no longer runs wolfCrypt's ML-KEM / X25519 benchmark. Key
      exchange is measured only between two machines: inside every handshake (X25519MLKEM768 in Stage 2,
      the pipeline and on the Pico), and across all five groups in the `tls` sweep.
    - **Collate:** `collate_results.py` lost the parsers for the removed families (June suite, `tls_bytes`,
      wolfCrypt key exchange) and the CROSS filter they needed. `all_results.csv` now has 5,842 rows from
      8 files, all from 28–29 Sep.
74. [Mac] The broker terminal now shows what reaches it. `./run_all.sh --serve-broker` prints one line per
    connection:
    - who connected, from which IP;
    - the listener, i.e. the certificate and TLS or mTLS;
    - for mTLS, the client certificate the client presented;
    - any handshake or certificate error.

    `--serve-broker --watch` also prints every message the brokers route: the Pico's unencrypted readings
    as text, and encrypted payloads as ciphertext. It is a second delivery of each message, so leave it
    off during timing runs. Tested locally with ML-DSA-44 over TLS and mTLS, plus 2 messages.
75. [Pico] Fourth Pico W run, with the step recorder. The hang came during **TCP connect**:
    `#watchdog connect mTLS: hung during TCP connect (connection 19)`. The broker's terminal showed no
    further connection from the Pico.
    - `WiFiClient::connect` gives up on its own after 5 s. So a call stuck for 8 s means the Pico's
      network stack (the CYW43 Wi-Fi driver / lwIP) stopped. It never got as far as a SYN the broker
      could accept; neither TLS nor the certificate type is involved.
    - Next check: the same run at 133 MHz (`--freq 133`). At the default 200 MHz the Wi-Fi chip's SPI
      clock is at the top of its range, which is a known suspect for Pico W Wi-Fi stalls. If the hangs
      stop there, the clock is the cause.

76. [Repo] The user's rule since 29 Sep: only signatures (PQC algorithms) are measured on one machine. Every TLS /
    mTLS handshake is a full MQTT connection through the broker on another machine, and LoRaWAN / AES / Ascon are
    measured only as messages through that broker.
    - **TLS sweep:** each handshake is now inside a full MQTT connection (CONNECT / CONNACK); the handshake-only
      mode of `mqtt_tls_timer` is gone.
    - **Removed as local:**
      - the `aead` stage (`aead_speed.c`, per-message and OTAA-join timings);
      - the wolfCrypt AES-GCM / Ascon throughput;
      - the Pico `aead_bench` and `wolfssl_bench`'s AEAD mode;
      - their results, the two Pico AEAD rows and logs, and the 28 Sep Mac run log. All went to
        `~/IoT-PQC-removed-2026-09-29/`.
      - The OTAA-join code went with its only user; git has it.
    - **The pipeline carries both directions:** `--dirs up,down` (default both), with a `Direction` column; on
      the host each downlink frame is sealed with Dir = 1 and verified after the broker delivers it.
    - **The Pico W's pipeline now protects its messages.**
      - The LoRaWAN / GCM / Ascon code moved from `aead_bench` into `mqtt_tls_bench/lora_aead.h`.
      - Each firmware runs 3 connect blocks, then 3 modes × 6 schemes × up / down pipeline blocks of
        3 + 1 connections × 200 messages.
      - Known-answer checks run on the board first.
      - `pico/tests/aead_host_test` checks all 48 frames (6 schemes × 2 directions × 4 sizes) byte for
        byte against the host's `app_aead.c`, AES-256-GCM included.
      - Firmware: 588 KB flash, 170 KB RAM free on the Pico W; 573 KB on the Pico 2 W.
    - **Checked:**
      - the `app_aead` self-test passes without the join code;
      - a pipeline through a temporary broker delivered and verified LoRaWAN 1.1 and Ascon frames in both
        directions (a smoke test, not counted);
      - the Pico parse test covers the new block labels.
    - `all_results.csv` now holds only signatures and broker runs: 4,979 rows from 5 files.
77. [Mac, Pico] Key sizes now follow one convention on every bench: raw key material, with no public key
    folded into the secret key.
    - **RSA:** the public key is the modulus; the secret key is the PKCS#1 DER private key (2048: 1,191 B
      OpenSSL / 1,194 B wolfSSL). It was the modulus length before.
    - **ECDSA:** the public key is the point x‖y (P-256: 64 B), as the Pico reports; the secret key is the
      scalar (32 B).
    - **ML-DSA (wolfSSL on the Pico):** wolfSSL's private length includes the public key (44: 3,872 = 2,560 +
      1,312); it now reports 2,560 / 4,032 / 4,896, as the Mac does.
    - **Ed25519 (wolfSSL) and Ed448 on the Pico:** these gave seed + public key (64 / 114 B); they now report
      the seed (32 / 57 B).
    - The recorded meta and `pico/logs/results.csv` rows were corrected by the same arithmetic, so the
      timings were not re-run. `stage1_customer_form_mac.csv` was regenerated.
78. [Mac, Pi, Pico] The key-exchange sweep covers 17 groups. The Pico W runs it, and every certificate its wolfSSL
    can handle. Stage 2 and the pipeline keep the customer's X25519MLKEM768; only the `tls` sweep varies the group.
    - **Groups** (`mqtt_bench.SWEEP_GROUPS`, one list for the broker, `tls_sweep.sh` and the Pico):
      - pure ML-KEM-512 / 768 / 1024;
      - the IETF hybrids X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024;
      - oqs-provider's hybrids SecP256r1MLKEM512, x25519_mlkem512, p384_mlkem768, p521_mlkem1024, x448_mlkem768;
      - classical X25519 and P-256;
      - HQC-1 / 3 / 5 (NIST's 2025 pick) and FrodoKEM-640-AES.
    - **Not BIKE:** oqs-provider lists `bikel1`, but the OpenSSL client refuses it in TLS 1.3 ("no suitable groups").
    - **The broker's group list is `?`-optional** (OpenSSL 3.5+). A broker without oqs-provider still starts:
      its native groups work, and the oqs-only ones fail with a handshake alert, recorded as failure rows.
    - **Checked (smoke test, not counted):** all 17 groups completed mTLS connections to a temporary broker on
      this Mac (ML-DSA-44 certificate). Without oqs-provider on the broker, X25519MLKEM768 and SecP384r1MLKEM1024
      connected, and hqc1 / p521_mlkem1024 failed cleanly.
    - **Pico W sweep:** `mqtt_tls_bench` gains `#block sweep <TLS|mTLS> <group>` blocks, 20 connections + 2
      warm-up (`MT_SWEEP_ITERS` / `MT_SWEEP_WARMUP`). They run after the pipeline, for the 13 groups wolfSSL has:
      every ML-KEM group plus X25519 / P-256; HQC and FrodoKEM are not in wolfSSL.
      - The Pico's wolfSSL now builds ML-KEM-512 / 1024, standalone ML-KEM, the extra hybrids and Curve448.
      - P-256 / 384 / 521 use SP assembly on both chips.
      - The runner writes `results/tls_handshake_pure_pico_<board>.csv` + meta, in the host sweep's columns (no TCP
        segment counts); `collate_results.py` labels them wolfSSL.
    - **Pico W certificates:** RSA-2048, RSA-3072, Ed25519, ML-DSA-65, ML-DSA-87 and Falcon-1024 join ECDSA-P256,
      ML-DSA-44 and Falcon-512.
      - RSA builds add RSA-PSS (TLS 1.3 needs it); RSA-3072 enables the 3072-bit SP code.
      - Not possible on the Pico: SLH-DSA (the broker can't serve it, finding 12) and MAYO / SNOVA (not in wolfSSL;
        SNOVA since: finding 106).
    - **Firmware:** all 9 compile for both boards. Pico W: 598–646 KB, 170 KB RAM free; Pico 2 W: 587–635 KB. None
      has run on hardware yet.
    - `pico/tests/mqtt_parse_test.py` now covers sweep blocks, their summary and collate rows, and checks that the
      sketch's group names are the host's.

79. [Pi, Pico] Clock cycles on every signature bench that can count them.
    - **Already counting:**
      - Stage 1 (`sig_speed.c`: OpenSSL, liboqs and wolfSSL backends): `perf_event_open` user-space cycles
        on Linux. `run_all.sh` sets `kernel.perf_event_paranoid=1` when `sudo -n` allows it.
      - Every Pico signature sketch (27 of 27 OK rows have cycles).
    - **Added:** the generic reference harness (`bench_template.c`: SDitH, FAEST, QR-UOV) uses the same perf
      counter. `run_reference_benchmarks.py` writes `cycles` per sample and `mean_cycles` / `median_cycles` per
      label, `parse_native_output.py` keeps those columns, and `to_customer_form.py` maps them to `*_mean_cyc` /
      `*_median_cyc`.
      - Checked on the Mac with a stub `api.h`: it compiles without warnings and reports 0 cycles, as there is no
        counter there. Linux-style values reach the customer form.
      - The Linux branch will first compile on the Pi.
    - **No cycles:** HAWK and MQOM (their own benches report time) and SQIsign (`NO_CYCLE_COUNTER`: its
      `PMCCNTR_EL0` read crashes on the Pi). macOS reports 0 without root.
    - **Workbook** (`PQC_Experiment.xlsx`, not in git): Pico and Pi only, in the user's edited layout (29 Sep).
      The Mac's Stage 1 files stay in `results/` but are no longer put in it.

80. [Pi, Pico] The advisor's comments (30 Sep): AES compared at 128 vs 256 bits per mode, and key exchange beyond ML-KEM.
    - **Payload schemes (9, host and Pico):**
      - none;
      - CTR + CMAC: LoRaWAN 1.0.x and 1.1 (AES-128), plus `aes256ctr`, the 1.0.x frame with AES-256-CTR and an
        AES-256-CMAC MIC (not standard LoRaWAN: a what-if);
      - AES-128/256-GCM;
      - AES-128/256-CCM (new; the AEAD of BLE, Zigbee and 802.15.4): 13-byte nonce, 16-byte tag;
      - Ascon-AEAD128.
    - **Ascon:** NIST standardised only the 128-bit-key AEAD. The "256" in the family is Ascon-Hash256, a hash;
      Ascon-80pq (160-bit key) was left out.
    - **Checked:**
      - known answers for CMAC-256 (SP 800-38B) and CCM (SP 800-38C example 1), on the host and in the Pico's
        on-board `la_kat()`;
      - `pico/tests/aead_host_test`: all 72 frames (9 schemes × 2 directions × 4 sizes) are identical between the
        Pico's BearSSL code and the host's OpenSSL code;
      - Pico W firmware +4.5 KB.
    - **Pico run:** 54 pipeline blocks (83 blocks in all), about 43,000 frames, still under one FCnt's 65,536.
    - **KEM exchange as MQTT messages (`kex` stage):** Classic McEliece's public keys (261,120 – 1,357,824 B) can't
      be a TLS 1.3 key share (at most 65,535 B), so it gets its own exchange through the broker. HQC and ML-KEM-768
      are measured the same way for comparison; HQC also stays in the TLS sweep.
      - The client (`mqtt_tls_timer`, `KEM=`) makes a key pair and publishes the public key. The responder next to
        the broker (`KEM_RESPOND=1`, started by `--serve-broker`) encapsulates. The client decapsulates and checks
        a SHA-256 of the secret.
      - Smoke test through a temporary broker on this Mac (not counted): all three KEMs tried (ML-KEM-768, HQC-1,
        Classic-McEliece-348864) agreed on the secret. Classic-McEliece-348864's key pair took about 134 ms here.
      - The Pico can't take part: a McEliece public key is larger than its RAM, and its wolfSSL has no HQC.
    - **SIKE** is not benchmarked: broken in 2022 (key recovery in about an hour on one core), withdrawn by NIST,
      removed from liboqs.
    - **Slides:** 1, 6, 7, 14, 15, 17, 18, 24, 26 and 36 updated, and slide 25 "Key Exchange beyond ML-KEM" added, in
      the user's edited deck.

81. [Pi, Pico] The first Pi run (Pi 4) and a Pico run, 30 Sep:
    - **The Pico stage skipped a connected board.** `run_all.sh` tested for it with `ls` over the serial port and
      both BOOTSEL drives, which fails whenever one path is missing (always `/Volumes/RP2350` with an RP2040);
      `pico_present()` now tests each path. When the BOOTSEL drive is hidden from the terminal (the macOS Removable
      Volumes permission), the runner also asks the chip with `picotool info -d`.
    - **MQOM round 3 (liboqs main) crashes on the Pi 4** with "Illegal instruction": its NEON code is compiled with
      `-march=armv8-a+crypto+sha3`, and the Pi 4's Cortex-A72 has neither the AES nor the SHA-3 instructions. The
      Stage 1 table now records such a crash as `CRASH(SIGILL)` instead of dropping the algorithm.
    - **QR-UOV needed `-fopenmp` on the Pi** (the user's commit). Its one `#pragma omp parallel for` would then use
      all four cores, so the harness now runs every reference bench with `OMP_NUM_THREADS=1`. macOS drops the flag
      (Apple clang has no OpenMP).
    - **OpenSSL errors that mean "this key couldn't be read"**: when oqs-provider isn't loaded, OpenSSL reports a
      MAYO / SNOVA / Falcon key as `EE certificate key too weak` (verification) or `ee key too small` (loading a
      client certificate). The Pi's round-3 and sweep failures (MAYO1/2 and SNOVA undecodable, MAYO3/5 decoded but
      failing their signature check, `unsupported group` for hqc* and SecP256r1MLKEM512) point to its client loading
      an older oqs-provider rather than the pinned or round-3 one. On the Mac, the same round-3 and main
      connections work at OpenSSL's default settings.
    - **wolfSSL Falcon-1024 mTLS: "Buffer error" on the Pi** only; 30 of 30 handshakes worked on the Mac.
    - The round3 stage now builds the client itself, so it no longer runs the previous stage's binary.
    - **Cause of the Pi's round-3 and sweep failures (diagnosed from its results):**
      - The Pi's default oqs-provider was an older system-wide build, `8b87173` on liboqs 0.15. Its group names
        differ (`p256_mlkem512`), liboqs 0.15 has HQC switched off, and its codepoints differ from the broker's
        `c174ed7`: 190 of 646 sweep rows failed. `run_all.sh` now uses the pinned `c174ed7` on liboqs 0.16 on every
        machine (`prov_pinned`: built once in the cache when the machine's own provider is another build).
      - Since 29 Sep the MQTT client linked liboqs (the KEM exchange). On Linux, oqs-provider loaded into that
        process called the client's liboqs 0.16 instead of its own, so the round-3 provider ran round-2 MAYO /
        SNOVA: MAYO1/2 and SNOVA keys (new in round 3) didn't decode, and MAYO3/5 signatures didn't verify.
        macOS keeps each library's links separate, which is why the Mac never showed it. The KEM exchange now has
        its own binary, `mqtt_kem_timer`, and `mqtt_tls_timer` never links liboqs.
      - The Pi's QR-UOV rows ran with `-fopenmp` (multi-threaded): re-run with the single-thread setting.
    - **What held up on the Pi 4:**
      - the pipeline: 234 of 234 rows OK, 9 schemes, both directions;
      - the KEM exchange: all 9 KEMs OK; Classic McEliece key generation 0.24–9.6 s;
      - Stage 1: 145 rows, 131 with CPU cycle counts;
      - Stage 2 except the expected SLH-DSA / wolfSSL-MAYO-SNOVA rows and wolfSSL Falcon-1024.
82. [Mac, Pi] Found in the Pi 4 results (1 Oct), and changed:
    - **The CA certificate went out in every handshake.** OpenSSL fills a certificate's chain from its own trust
      store. The broker (and the OpenSSL client) trusted the same CA that signed its certificate, so it sent that CA
      too, although the peer already holds it: for every certificate type, the CA's full size each way.
      - Size: 0.4 KB with ECDSA-P256, 4.0 KB with ML-DSA-44, 7.5 KB with ML-DSA-87.
      - Who saw it: the Pico downloaded it too (4 KB of its 11.8 KB ML-DSA-44 handshake). The wolfSSL clients
        send only their own certificate.
      - The fix: `gen_certs.sh` now makes two CAs per algorithm. `CA` signs the server certificate and is what
        clients trust; `ClientCA` signs the client certificate and is what the broker trusts.
      - Checked locally with both clients: ML-DSA-44 TLS download 11,822 → 7,812 B, OpenSSL mTLS upload 11,973 →
        7,970 B, all connections OK.
      - It needs new certificates (`bash scripts/gen_certs.sh`, then copy them to the Pi), so results before and after
        differ in bytes.
    - **MQTT CONNECT after TLS took 25–75 ms** on the Pi 4 against 10.6 ms without TLS. The suspected cause is
      Nagle's algorithm on the broker: after the TLS 1.3 session tickets, the small CONNACK waits for the client's
      delayed ACK. The broker config now has `set_tcp_nodelay true` (our clients already set `TCP_NODELAY`). This
      is untested between two machines: if it is the cause, MQTT CONNECT drops to about 10 ms, while the handshake
      times stay the same.
    - **The KEM exchange now includes the customer's X25519MLKEM768, and X25519 alone.** It is built in
      `mqtt_tls_timer.c` (`kem_new`) from liboqs ML-KEM-768 and OpenSSL's X25519, laid out as in
      draft-ietf-tls-ecdhe-mlkem [13]:
      - public key = ML-KEM key | X25519 share (1,216 B);
      - ciphertext = ML-KEM ciphertext | X25519 share (1,120 B);
      - shared secret = both secrets (64 B).
      X25519 works as a KEM the way TLS uses it: the ciphertext is the responder's ephemeral share. Both are in
      `--kex`'s default list.
    - **wolfSSL's small Curve25519 code on the Pico.** The TLS firmware builds wolfSSL with `CURVE25519_SMALL`,
      and `wolfssl_bench` builds Ed25519 with `CURVED25519_SMALL`: both are the slow, small-footprint variants. The
      Pico's X25519 cost in the sweep (about 990 ms per handshake, against 168 ms with ML-KEM-768 alone) is
      therefore partly our build setting.
    - **The Pico W now runs the KEM exchange too.** A separate firmware (`-DMT_KEX_ONLY`, `kem_wolf.h`, wolfCrypt)
      runs ML-KEM-512/768/1024, X25519 and X25519MLKEM768 against the same responder next to the broker. A second
      firmware builds the small Curve25519 code for the A/B. The TLS firmware is unchanged (same free RAM). `pico/tests/kem_host_test` runs the wolfCrypt side against liboqs + OpenSSL on the host: the same
      secret for every KEM.
    - **Runner bugs found in the 30 Sep – 1 Oct Pico run:**
      - It stopped reading a board after 8 serial reconnects. Every watchdog reboot is one, so 6 of the 9
        certificates lost the end of their sweep (ML-DSA-44's is complete). MQTT firmware now allows 100 (one per
        block).
      - The pipeline rows took the scheme from the `#aead` description instead of the `#block` name. They have been
        re-saved from the logs.
      - A reset that isn't the watchdog's (RSA-3072, once) starts the plan over. The fullest run of each block is now
        kept, not both.
    - **Pico Falcon-1024:** TLS hung before its first connection, and mTLS fails with wolfSSL's "Buffer error", as the
      Pi's wolfSSL client did once on 30 Sep.
    - **The A/B (Pico KEM exchange, 1 Oct), per operation:**

      | | small code | wolfSSL's default code |
      |---|---|---|
      | X25519 key pair | 424 ms | 57 ms |
      | X25519 shared secret | 424 ms | 57 ms |
      | X25519MLKEM768 exchange | 892 ms | 152 ms |

      ML-KEM-768 alone is 41 ms. So the Pico's ~1 s X25519 handshakes were mostly the small code.
    - **Pico builds now use wolfSSL's default Curve25519 / Ed25519 / X448 code;** `-DWB_SMALL_25519` brings back the
      small one. It costs a few KB of flash on a 2 MB chip. Pico results with X25519, Ed25519 or X448 from before
      1 Oct used the small code.
83. [Pi, Pico] **The handshake's own crypto, timed in the same run.**
    - What changed: every connection row of a wolfSSL client (the Pico W, and the Pi's wolfSSL client on Linux) now
      splits the TLS handshake into the client's crypto calls. There are four sums, each with a call count:
      - key share (the ML-KEM, X25519, X448 or ECDH key pair; a hybrid makes two);
      - its completion (ML-KEM decapsulation, X25519 / ECDH shared secret);
      - signature verification (the broker's certificate chain and CertificateVerify);
      - signing (the client's CertificateVerify in mTLS).
    - How: `pico/sketches/mqtt_tls_bench/hs_timing.c` wraps 21 wolfCrypt entry points with the linker's `--wrap`, so
      wolfSSL's own calls during the real handshake are clocked. wolfSSL's code is unchanged.
    - What the rest means: `tls_ms` minus these sums is the network, the broker's work (encapsulation, its signature)
      and the protocol.
    - Where it runs:
      - Pico: every MQTT firmware (the runner adds the `--wrap` flags).
      - Pi: `build_timer.sh` links a static wolfSSL (`--enable-static` in `build_wolfssl.sh`), and falls back to
        the build without timing if that link fails.
      - Not on macOS (its linker has no `--wrap`), and not for the OpenSSL client.
    - **Pi 4 (1 Oct, wolfSSL client, ML-DSA-44, X25519MLKEM768), per connection:**

      | | handshake | key share | completion | verify | sign | rest |
      |---|---|---|---|---|---|---|
      | TLS | 18.5 ms | 0.31 ms | 0.68 ms | 0.88 ms | - | 16.6 ms |
      | mTLS | 20.2 ms | | | | 1.01 ms | |

      The rest (network, broker and protocol) is about 90% of the handshake.
    - Results: columns `hs_keygen_us .. hs_sign_n` in Stage 2, the pipeline and the Pico sweep. Collate turns them into
      the operations "handshake: key share / key share completion / verify / sign (client)".

84. [Pico] **wolfSSL's own Falcon in the signature bench.** `wolfssl_bench` now runs Falcon-512 / -1024 (the TLS client's
    code), 5 iterations. It counts failed signatures and signs again instead of stopping, to show whether
    the Pico's Falcon-1024 mTLS "Buffer error" comes from signing itself. wolfSSL retries an over-long signature up to 32
    times. The "Buffer error" also comes from a bound on its signing loop, and on the Pico that loop runs with floating
    point emulated in integers.
    - **Result (1 Oct):** both sizes signed 5 of 5 with no retries.
      - Falcon-512: sign 992 ms, verify 7.0 ms. Falcon-1024: sign 2.16 s, verify 14.4 ms.
      - Falcon-1024 signing alone peaks at 116 KB of heap (Falcon-512: 59 KB). The TLS client already holds 40-75 KB,
        and the failed mTLS handshake had reached 138 KB.
      - So the Pico's Falcon-1024 mTLS failure is most likely running out of RAM in the client's signature, not
        signing itself.
    - **Ed25519 with wolfSSL's normal code** (the Pico's default since 1 Oct): sign 26.7 ms, verify 65.5 ms, against
      431 / 895 ms with `CURVED25519_SMALL`.

85. [Pico] **The Pico W's full MQTT run against the Mac's brokers (1-2 Oct).** Two CAs, `set_tcp_nodelay`, wolfSSL's
    normal curve code and the handshake crypto timed (findings 82-84). 9 certificates × (Stage 2, the pipeline, the
    13-group sweep), plus the KEM exchange. The broker Mac was on macOS 27.0.1 (Mosquitto 2.1.2, OpenSSL 3.6.4,
    oqs-provider c174ed7, as before).
    - **Every certificate connects over TLS and mTLS, Falcon-1024 included:** 20 mTLS connections, 2.47 s handshake.
      Its 1 Oct failure (finding 84) did not come back.
    - **Handshake (median):** TLS 225-413 ms, mTLS 406 ms (Ed25519) to 3.59 s (RSA-3072).
      - 66-98% of a handshake is the Pico's own crypto (Pi 4: about 10%).
      - The X25519MLKEM768 key share + completion is about 137 ms on every certificate.
      - mTLS signing: Ed25519 28 ms, ECDSA-P256 43 ms, ML-DSA-44 0.16 s, ML-DSA-87 0.36 s, RSA-2048 0.97 s,
        Falcon-512 1.0 s, Falcon-1024 2.19 s, RSA-3072 3.20 s.
      - ML-DSA-44, per connection (24 TLS / 19 mTLS connections):

        | | handshake | key share | completion | verify | sign | rest |
        |---|---|---|---|---|---|---|
        | TLS | 284.8 ms | 66.6 ms | 70.7 ms | 58.5 ms | - | 88.6 ms |
        | mTLS | 501.3 ms | 66.7 ms | 70.7 ms | 58.5 ms | 158.9 ms | 148.4 ms |
    - **RSA mTLS counts 3 verifies:** after an RSA signature wolfSSL checks it (`VerifyRsaSign`, "check for signature
      faults", `tls13.c`), about 26 ms with RSA-2048 on the Pico.
    - **MQTT CONNECT after mTLS takes longer (16-60 ms, TLS 14-25 ms):** a TLS 1.3 client sends CONNECT right after
      its Finished, so the broker's check of the client certificate, and the rest of its upload, land in this step.
    - **Key-exchange groups (ML-DSA-44, TLS):** ML-KEM-512 / 768 / 1024 156-192 ms, X25519 258 ms, X25519MLKEM768
      284 ms, the P-384 / P-521 / X448 hybrids 584-916 ms.
      - The Pico's own key-exchange crypto per group (median over all 9 certificates): ML-KEM-768 22.8 ms,
        X25519 113.9 ms, X25519MLKEM768 136.7 ms, P-521 + ML-KEM-1024 742 ms.
      - On the RP2040 the curve, not ML-KEM, is the expensive half.
    - **The two ML-KEM-512 hybrids fail on their TLS IDs:**
      - wolfSSL 5.9.4 uses 0x2F4B (SecP256r1MLKEM512) / 0x2FB6 (X25519MLKEM512).
      - oqs-provider c174ed7 uses 0x11E9 / 0x11EA (`draft-rosomakho-tls-ecdhe-mlkem512`).
      - The broker answers with a fatal alert. The P-384 / P-521 / X448 hybrids share their IDs (0x2F4C / 0x2F4D /
        0x2FB7) and work.
    - **KEM exchange (50 each):**
      - ML-KEM-512 / 768 / 1024: 31.3 / 35.9 / 49.6 ms.
      - X25519: 125.6 ms. X25519MLKEM768: 150.6 ms (888.2 ms with the small Curve25519 code).
      - The small code saves 14.2 KB of flash and 412 B of stack in this firmware.
    - **Payload (uplink, median of the 18 TLS / mTLS runs):**
      - Ascon seal / open 92 / 157 µs. AES-128-GCM 413 / 620 µs (4.5×).
      - AES-256 adds 25-37% to sealing.
      - Broker round trip 10.7 ms over Wi-Fi.
    - **Wi-Fi stalls:** 10-18 of the 83 blocks per certificate ended in a TCP-connect stall (8 on 30 Sep - 1 Oct).
      - The watchdog reboots the board, and the block keeps its complete connections (PARTIAL, n shown).
      - The ML-DSA-44 sweep has no TLS P-256 and no mTLS P-521 + ML-KEM-1024 connection.
    - **The Mac after its macOS 27 update has no Rosetta:** arduino-cli's x86_64 `ctags` failed every compile ("bad
      CPU type in executable"). It was rebuilt natively from `arduino/ctags` tag 5.8-arduino11.
    - **ML-DSA-44 run again (2 Oct, same Mac broker, `--algo ml-dsa-44`)** to fill the sweep gaps. It stalled in 16 of 83
      blocks again: TLS P-256 now has 7 handshakes and mTLS P-521 + ML-KEM-1024 has 4, but mTLS X25519MLKEM768 now has
      none.
      - The rerun replaced ML-DSA-44's rows in `results/*_pico_rp2040.*`. The first run's rows are kept in
        `results/pico_rp2040_mldsa44_run1_rows.json`, saved from the workbook.
      - The slides use the rerun: TLS 284.0 ms (32 connections), mTLS 461.4 ms (14), ML-DSA-44 signing 90.5 ms (first
        run 158.9 ms; ML-DSA signing time varies). The one empty sweep block (mTLS X25519MLKEM768) shows the first
        run's 526.3 ms (7), marked †.
    - **A run against another broker:** `run_benchmarks.py --tag <name>` keeps it apart, in
      `results/*_pico_<board>_<name>.*` with logs in `pico/logs_<name>/` (from `run_all.sh`:
      `PICO_ARGS="--tag pi_broker"`).

86. [Pico, Pi] **The Pico W against the Pi 4's brokers (2 Oct, `--tag pi_broker`).** The same firmware, certificates
    and broker settings as finding 85, with `./run_all.sh --serve-broker` on the Pi (192.168.50.132). Both brokers are
    on Wi-Fi (the Mac's `en0`, the Pi's Wi-Fi), so the Pico's traffic crosses the same kind of link either way.
    - **Every connect and pipeline block completed:** 50 / 50 TLS and mTLS connections for all 9 certificates, and 342 of
      342 pipeline blocks OK. The run had 9 Wi-Fi stalls in all, against 99 with the Mac as broker. With both brokers on
      Wi-Fi, the stalls depend on the broker machine, not only on the Pico's Wi-Fi stack (candidates on the Mac: its Wi-Fi
      power management, its firewall, macOS 27's network stack; not checked).
    - **The Pico's handshake hardly changes:** within a few % per certificate (ML-DSA-44 TLS 283.7 ms vs 284.8, mTLS 511.2
      vs 501.3), because the Pico's own crypto dominates it.
      - The exception is RSA-3072 TLS: 362.0 vs 317.6 ms. Its rest (network + broker + protocol) is 109 vs 66 ms: the
        broker's RSA-3072 signature, now on the Pi.
    - **The network part is faster through the Pi:** a message round trip is 6.7 ms (Mac 10.7 ms), and a plain MQTT
      connection takes 12.7 ms (29.3 ms).
    - **KEM exchange:** the Pi's responder encapsulates in 0.16-2.0 ms (the Mac: 0.03-0.6 ms). The exchange totals stay
      close: ML-KEM-768 33.1 ms (35.9), X25519MLKEM768 152.9 ms (150.6).
    - **The two ML-KEM-512 hybrids fail the same way:** the Pi's oqs-provider is the same build, with the same TLS IDs.
    - **ML-DSA-44 was run a second time** (`--algo ml-dsa-44`, same broker). That replaced its rows and the plain MQTT
      reference, all 50 / 50 again. This run's sweep never had gaps: its only failures are the two ML-KEM-512 hybrids.
      The gaps (TLS P-256, mTLS P-521 + ML-KEM-1024) are in the Mac-broker run of finding 85.
    - Slides: a Pico W → Pi 4 copy of each Pico W → Mac slide (key-exchange groups + chart, Remote MQTT Results, MQTT over
      TLS / mTLS, AES and Ascon), "Pico W → Mac vs Pico W → Pi 4 Broker", and the Pico → Pi column of "Remote TLS/mTLS
      Results".
    - Files: `results/*_pico_rp2040_pi_broker.*`, logs in `pico/logs_pi_broker/`. The Pi's broker is Mosquitto
      2.0.21 on OpenSSL 3.5.6 with oqs-provider c174ed7 (`results/versions_pi_remote.json`).

87. [Mac, Pi, Pico] **Parameter check against NIST round 3 (2 Oct 2026).** Round 3 (May 2026) kept nine candidates
    and gave the teams until 14 Aug 2026 to change their parameters [37]. Against what this repo ran before:
    - **Changed, now run as round 3 everywhere:** MAYO-1 / MAYO-2 (pk 1,420 → 1,456 B and 4,912 → 2,928 B; sig 454 →
      464 and 186 → 239 B), SNOVA (new sets I / III / V × K / B / S on (v, o, q, l, r, m1), aimed at the wedge
      attack that broke most round 2 sets [38]), MQOM v3 [34] and UOV-Ip / III / V (Ip: pk 278,432 → 321,300 B, sig
      128 → 135 B). The host runs them from liboqs main `b196b57a` (directly, and through oqs-provider `36cafae`);
      the Pico now runs the same commit, memory-optimised (`LIBOQS_ROUND=3`). The round 2 sets are no longer run.
    - **SNOVA on the Pico W (RP2040, 200 MHz, liboqs main, memory-optimised, 10 runs each; 2 Oct):** all 9 round 3
      sets run, where no round 2 set fit. Signing takes 1.1-1.5 s at level I, 3.1-3.2 s at III and 4.9-5.3 s at V;
      verifying 0.8-1.0 s, 2.2-2.3 s and 3.3-3.5 s. Peak stack is 26-40 KB (level I), 49-60 KB (III) and 77-93 KB
      (V) when signing, at most 18 KB elsewhere: under the 120 KB the SNOVA team gives for level V [32].
    - **MQOM v3 on the Pico W (cat 1, constant time):** GF(16) fast signs in 5.2 s and verifies in 5.0 s, GF(16)
      short 23.7 / 23.6 s, GF(2) shorter 61.1 / 40.1 s, with at most 28 KB of stack.
    - **MAYO round 3 on the Pico W:** MAYO-1 hung at its first keygen with a 224 KB stack (round 2 MAYO-1 fit), and
      took the next flash (MAYO-2) with it: the runner's USB reset can't reach a board whose USB died. The runner
      now waits for a manual BOOTSEL there, and `liboqs_bench` reboots itself into BOOTSEL after such a hang. The
      cause was the stack (finding 95).
    - **QR-UOV cat1** now runs from `qruov_zoo_bench` with a 64 KB stack: the same times as its old sketch (sign
      1.20 s, verify 1.08 s).
    - **Still older code here:** SDitH (2023 threshold variant; round 3 is SDitH v3, Aug 2026), FAEST (2.0; round
      3 is FAEST 3.0, 31 Aug 2026), SQIsign (round 2 commit; its round 3 version is 1 Sep 2026), QR-UOV (round 2
      package; NIST hosts the round 3 one) and the Pico's UOV-Ip classic sketch (round 2 keys and code). Each needs
      its new source ported (SDitH v3 moved to its own CMake + benchmark build).
    - **HAWK has been withdrawn** by its team from the NIST process [37]; its rows stay as measured.
    - **Eliminated in round 3:** CROSS, LESS, Mirath, PERK, RYDE. None of them is benchmarked here.

88. [Pico, Pi] **The second Pico W run against the Pi 4's brokers (`pi_broker2`, 2-3 Oct): checked, valid.** RSA-2048 to
    ML-DSA-65 were flashed from the Mac until it kernel-panicked; ML-DSA-65 to Falcon-1024 and the KEM exchange were
    then run from the Pi (the runner merges per signature, so ML-DSA-65's partial rows were replaced).
    - **Complete:** 19 connect rows (9 certificates x TLS / mTLS + plain), each n = 50, all OK; 342 / 342 pipeline blocks
      OK with 600 messages each; 234 sweep rows; 7 / 7 KEM exchanges, n = 50. No duplicate rows.
    - **Repeatable:** 16 of the 18 handshake medians (all 9 TLS, 7 of 9 mTLS) are within 2% of the first Pi-broker run
      (finding 86); the other two are ML-DSA-65 and ML-DSA-87 mTLS (below). The message round trip is 6.5 ms (6.7), seal / open medians agree to 0.2%, and the KEM
      exchange totals agree (ML-KEM-768 31.5 ms, X25519MLKEM768 151.4 ms). The flashing host (Mac or Pi) makes no
      difference.
    - **ML-DSA mTLS moves between runs, in both directions** (ML-DSA-65 772 vs 644 ms, ML-DSA-87 791 vs 897 ms): only
      the Pico's signing changes. ML-DSA signs by rejection sampling, so one signature takes 52-480 ms (ML-DSA-44,
      10th-90th percentile); with 50 connections the median signing time moved by 8-60% between the two runs. Verify and
      key share are identical. Report ML-DSA mTLS from the two runs together, or with more connections.
    - **Sweep losses are not random:** besides the 36 expected ML-KEM-512 hybrid failures (9 certificates x 2 groups x
      TLS / mTLS), 3 blocks were lost and all are `p384_mlkem768`, the group right after those two failing hybrids. The
      first Pi-broker run lost 5 of its 6 blocks the same way. After two refused handshakes, the Pico's next TCP connect
      stalls (watchdog). Moving the two hybrids to the end of the sweep would stop them taking a measured group down.
      One more block, Falcon-1024 TLS with SecP384r1MLKEM1024, stopped after 12 of 20 connections with wolfSSL's Buffer
      error: the largest certificate with the largest key share, near the RP2040's RAM limit.
    - **Fixed in the runner:** the KEM-exchange firmware prints no wolfSSL version, and as the last sketch it overwrote
      `versions_pico_rp2040_pi_broker2.json` with an empty one (the sweep rows then read "OpenSSL (version not
      recorded)" in `all_results.csv`). The runner now keeps the recorded version; this run's file was restored to
      5.9.4, the version its own KEM rows carry.
89. [all] **Falcon / FN-DSA and fixed point (checked 3 Oct 2026).** On 28 Sep 2026 NIST's FIPS 206 team published a new
    plan for FN-DSA, for comment: key generation and signing in fixed-point arithmetic only (32.32 for key generation,
    64.64 for signing), one fully specified signing procedure that KATs can test, and no floating point in the FIPS
    itself; verification and key generation stay compatible [39, 40]. FIPS 206 is not final.
    - **Every Falcon in this repo is still the round 3 floating-point design:** liboqs 0.16 and main (PQClean-derived;
      `fpr` = IEEE-754 binary64 emulated with 64-bit integers in the clean code, native double in the aarch64 / avx2
      code), the Pico's PQClean sketch (integer emulation), wolfSSL 5.9.4 (its default integer `fpr` emulation on the
      Pico, `--enable-falcon=double` on the Mac and Pi), and OpenSSL through oqs-provider (liboqs). Emulating floating
      point with integers is not fixed point: it reproduces binary64 rounding.
    - **What changes when fixed-point FN-DSA lands:** verification is integer-only already, so the verify numbers stand.
      Signing and key generation numbers would need a re-run with a fixed-point implementation; none of liboqs (main,
      29 Sep), wolfSSL 5.9.4 or PQClean has one yet, and PQClean has since been archived.

90. [Pico, Mac] **SDitH, FAEST, SQIsign and QR-UOV moved to their round 3 code for the Pico (3 Oct 2026).** Each port was
    checked on the Mac before it reached a board: the Pico build's KAT file (100 key pairs, signatures, verifications)
    is byte-identical to the official round 3 code's.
    - **QR-UOV** (spec v3.0, `qruov_bench`): the package's reference code, with its OpenSSL SHAKE layer replaced by
      PQClean's FIPS202 (PRG = SHAKE). KAT-identical for all five level 1 sets. Round 3 needs far less memory than
      round 2: host stack peaks (keygen / sign / verify) are 27 / 25 / 21 KB (1q127L3), 31 / 29 / 24 KB (1q31L3),
      56 / 59 / 51 KB (1q127L10), 70 / 74 / 63 KB (1q31L10) and 114 / 122 / 102 KB (1q7L10), with no large static
      tables. All five sets now link for the RP2040; in round 2 only cat1 (1q127L3) fitted.
    - **SQIsign** (the "third-round version"; new primes p324 / p500 / p664 for levels I / III / V): its portable ref
      build with 32-bit field arithmetic (`GF_RADIX=32`; round 3 needs no GMP) and `SQISIGN_SINGLE_THREADED` (no thread-local
      storage on bare metal) is KAT-identical at all three levels. No heap; host stack peaks 73 / 102 / 39 KB (I),
      97 / 136 / 62 KB (III), 131 / 185 / 82 KB (V). All three link for the RP2040 (`sqisign_bench`). Round 2's
      SQIsign needed `__uint128_t` and could not be built for the Pico at all.
    - **FAEST 3.0** (31 Aug 2026, `faest_bench` regenerated by `update_src.sh`, 32-bit Keccak as its meson build picks):
      KAT-identical for 128f, EM-128f, 192f and 256f. But signing now needs a large heap: 341 KB (128f), 267 KB
      (EM-128f), 981 KB (192f), 1,587 KB (256f); verify about half. So no FAEST set fits the RP2040, only the two 128
      sets fit an RP2350, and 192f / 256f fit neither. (The old sketch's note, 2.4 KB of heap for FAEST 2.0, does not
      hold for 3.0.)
    - **SDitH v3** (Aug 2026): signing needs a 335 KB scratch buffer at cat 1 fast (959 KB short), verifying 329 KB,
      so it cannot run on the RP2040; on an RP2350 it would also need its `__uint128_t` GF(2^128) code ported to
      32-bit first. Recorded in the runner, not built; the round 1 `sdith_bench` is removed.
    - **On the Pico W (RP2040 at 200 MHz, 3 Oct), keygen / sign / verify medians:**
      - QR-UOV, all five sets OK (10 / 10 verified): 1q127L3 4.53 s / 0.79 s / 0.74 s, 1q31L3 6.31 / 1.02 / 0.96 s,
        1q127L10 12.3 / 3.36 / 3.21 s, 1q31L10 20.5 / 4.93 / 4.70 s, 1q7L10 63.5 / 11.5 / 10.9 s. The board's stack
        peaks match the host's (27.6 / 25.5 / 21.8 KB for 1q127L3 up to 116.7 / 124.8 / 105.1 KB for 1q7L10). Against
        round 2's cat1 on the same board (12.58 / 1.20 / 1.08 s), round 3's 1q127L3 is 2.8x faster at keygen and
        1.5x at signing and verifying.
      - SQIsign-I OK (5 / 5): 13.7 s / 40.1 s / 6.05 s, 103 KB of stack when signing.
      - SQIsign-III crashed in its first keygen (silent for the 3,600 s timeout); SQIsign-V wasn't reached. The
        cause was our library build, not SQIsign. `make_sqisign_lib.sh` merged the three levels into one archive, but
        each level defines the same 193 `sqisign_gen_*` functions (big integers, quaternions), each sized for its
        own integers (80 limbs at level III vs 60 at I). The linker took level I's copies, so III and V computed
        with level-I-sized integers and corrupted memory: a bus fault in `ibz_mod`, reproduced in QEMU. The Mac
        check had linked one level per program, which is why it passed. The script now renames each level's copies
        (`sqisign_gen_<level>_*`). In QEMU (the Pico's M0+ code on an MPS2 board, unaligned accesses trapped as on
        an M0+) all three levels then produce the same key pair and signature as a Mac build with the same RNG.
        They take keygen / sign / verify 2.7 / 8.1 / 1.2 G instructions (I; the board took 2.7 / 8.0 / 1.2 G
        cycles), 17.9 / 28.9 / 4.2 G (III) and 21.9 / 65.0 / 10.0 G (V): about 4.5 and 8 minutes per iteration on
        the Pico. Level I's board numbers stand, since it linked its own copies. The sketch now reboots into
        BOOTSEL on a hard fault, so a crash shows at once instead of as an hour of silence.
      - **After the fix (Pi-driven run, 3 Oct, commit `c4e4be35`): SQIsign-III and -V OK (3 / 3 each).** Medians:
        III 60.5 s / 149 s / 22.4 s, V 131 s / 380 s / 58.3 s. The board needed 1.0-1.2x the cycles QEMU counted
        as instructions (level I 1.0x); keygen varies most (III: 52-61 s), as it retries until it finds a key.
    - The host stage (`run_all.sh` reference stages) still uses the older code for these four.
91. [Mac, Pico] **LoRaWAN 1.1 with 256-bit keys (`lorawan11_256`, 3 Oct 2026).** The 1.1 frame with AES-256-CTR and the
    1.1 MIC rules on AES-256-CMAC: two CMACs per uplink (keys nwk | nwk2 and nwk2 | nwk), one per downlink. Like
    `aes256ctr` for 1.0.x, it is not standard LoRaWAN (AES-128 only): it shows what 256-bit keys cost in LoRaWAN's own
    construction. Host (OpenSSL) and Pico (BearSSL) frames are byte-identical (80 / 80 in `pico/tests/aead_host_test`,
    10 schemes x up / down x 4 sizes), and the host self-test passes. The pipeline now has 10 schemes (89 Pico
    blocks).
    - **Measured on the Pico W through the Pi 4's broker** (`pi_broker3`, ML-DSA-44 mTLS, 51 B payload, medians):
      sealing an uplink takes 928 us vs 696 us for `lorawan11` (+33%), opening it 1,085 vs 854 us (+27%). A downlink
      takes 570 vs 418 us (+36%) to seal and 726 vs 591 us (+23%) to open. Both send 112 B per message on the
      socket. The broker round trip (6.3-7.7 ms) is unchanged, so 256-bit keys cost only AES-256's extra rounds
      and key schedule: about 0.2-0.3 ms per frame on the Pico.

92. [Pico, Pi] **The third Pico W run against the Pi 4's brokers (`pi_broker3`, 3 Oct, ML-DSA-44): valid.** 83 of 89
    blocks OK. The 6 failures are the same as in `pi_broker2` (finding 88): the two ML-KEM-512 hybrids over TLS and
    mTLS, and p384_mlkem768, the group tested next, which then stalls. The other nine payload schemes repeat
    `pi_broker2` within 1% (seal / open). The TLS key-exchange sweep repeats it within ±1% (ML-KEM-768 166.0 vs
    165.7 ms). The mTLS sweep varies by up to ±21%, because ML-DSA signing time varies per signature
    (rejection sampling) and each group has 20 connections. Stage 2 TLS: 284 vs 283 ms.
93. [Pico] **Cycle counts over 21.5 s were wrong (fixed 3 Oct).** The sketches print cycles = us x MHz as a 32-bit
    `unsigned long`, which wraps past 2^32 cycles: 21.5 s at 200 MHz. 68 cycle values in 25 rows of
    `pico/logs/results.csv` had wrapped (RSA keygen, SLH-DSA 's' and 128s signing, MQOM, QR-UOV-1q7L10 keygen,
    SQIsign-I signing). The microsecond columns were always right. The runner now computes cycles from the
    microseconds and the CPU clock the board prints. The existing rows are corrected, each only after checking
    that us x MHz mod 2^32 equals the printed value.
94. [Pi, Mac] **The OpenSSL client's handshake broken down (3 Oct).** `network/hs_timing_openssl.c` gives
    `mqtt_tls_timer` on Linux the same `hs_*` columns as the wolfSSL clients (finding 83): key share, its
    completion, verify, sign, per connection. Per handshake it counts 1 key share (`EVP_PKEY_keygen`; a hybrid
    group is one provider key), 1 derive (`EVP_PKEY_derive` / `EVP_PKEY_decapsulate`), 2 verifies (the broker's
    chain through `X509_verify_cert`, and its CertificateVerify) and, for mTLS, 1 signature. OpenSSL also runs
    `X509_verify_cert` to build the client's own chain before sending it; that call is not counted.
    - Tested on the Mac through a test-only interposing library, against local brokers, 20 handshakes,
      X25519MLKEM768: ML-DSA-44 mTLS 1.56 ms = 0.08 keygen + 0.08 derive + 0.18 verify + 0.54 sign + 0.69 ms
      for the broker and loopback. Ed25519: 0.85 ms with 0.03 ms of signing. The Pi's rows come from its next
      `mtls` / `pipeline` run.
95. [Pico] **Why MAYO round 3 hung on the Pico W: its stack (3 Oct).** Run in QEMU, the Pico's own M0+ build of liboqs
    main needs (keygen / sign / verify) 158 / 236 / 225 KB of stack for MAYO-1 and 125 / 153 / 363 KB for MAYO-2.
    It gets there with no faults and no heap, at 70 / 138 / 47 M instructions for MAYO-1 (about 0.35 / 0.7 /
    0.24 s on the Pico).
    - The sketch had given both 224 KB, so MAYO-1 overflowed while signing; no output appears until the first
      keygen-sign-verify round ends.
    - MAYO-1 now gets 240 KB: about the most the RP2040 can give (the sketch's other static RAM is 9 KB, and 7 KB
      stays free for the heap).
    - MAYO-2's verify needs more than the RP2040's whole 264 KB of RAM, so MAYO-2 now runs only on the RP2350.
    - **On the board with 240 KB (3 Oct): MAYO-1 OK, 10 / 10.** Medians 0.44 s keygen, 0.79 s sign, 0.37 s verify:
      1.3 / 1.1 / 1.6x the cycles QEMU predicted as instructions. MAYO reads large tables, so the M0+'s two-cycle
      loads and the flash cache cost more here than in SQIsign's arithmetic.
96. [Pico, Mac] **UOV-Ip round 3 on the Pico (7 Oct): `uov_bench`, classic, keys in flash.** Round 3 UOV-Ip
    (n = 119, o = 45) has a 321,300 B public key and a 278,087 B secret key; key generation holds both (~600 KB), so
    `make_uov_keys.sh` builds liboqs main (the Pico's round 3 commit, UOV-Ip only) on the host, makes the pair from a
    fixed seed, checks sign / verify / a changed message, and writes it as const arrays. The sketch links the Pico's
    round 3 liboqs (now with `SIG_uov_ov_Ip`) and signs / verifies with the keys read straight from flash.
    - QEMU (the M0+ build, unaligned accesses trapped): sign 17.4 M instructions with 12 KB of stack, verify 7.8 M
      with 5.3 KB, no heap, changed messages refused: about 0.1 s and 0.05 s on the Pico before flash-cache misses.
    - Builds for both boards: 727 KB of flash (34% of the Pico W's), 42 KB of static RAM. Not yet run on a board.
    - It replaces the round 2 `uov1_bench` (pqov sources, round 2 keys). UOV-Ip-pkc stays RP2350-only: its verify
      expands the compressed key into RAM.
97. [Mac, Pi, Pico] **The four deployment items, built (7 Oct): `gen_certs.sh --deploy`, `mqtt_bench.py --deploy`,
    run_all's `deploy` stage, the Pico's `-DMT_DEPLOY` firmware.** How they work: how_it_works.md, `deploy`.
    - On the Mac, with the Pico's own wolfSSL settings (`pico/tests/deploy_host_test`): the broker's IP accepted and
      a wrong one refused (`wolfSSL_check_domain_name` refuses IP literals in 5.9.4, so IPs go through
      `wolfSSL_check_ip_address`); `revoked.crt` accepted without the CRL and refused with it; `expired.crt`
      refused; the signed trust-anchor update verified and refused with any changed byte; ML-DSA-44 signatures cross
      between wolfCrypt and OpenSSL both ways.
    - On the Mac, end to end (`mqtt_bench.py --role both --deploy`, OpenSSL client, 5 connections each): TLS
      1.13 ms, TLS-checked 1.24 ms, mTLS 1.33 ms, mTLS-checked 1.62 ms; the three bad connections refused (IP
      address mismatch, certificate revoked, certificate has expired); the KEM exchange OK plain, over mTLS and
      signed. Signed, the device signs in 0.23 ms (ML-KEM-768) to 0.43 ms and verifies in 0.08-0.10 ms; the round
      trip grows from 0.22 to 0.86 ms with the responder's own check and signature.
    - The retained update reaches a subscriber intact (6,429 B). The Pico firmware builds (672 KB of flash, 136 KB
      of static RAM, 64 KB LittleFS); the benchmark firmware is unchanged (92 KB static RAM, as before).
    - Not yet run on the Pico or between the Pi and the broker.
98. [all] **Round 4 (checked 7 Oct 2026).** NIST's additional-signatures process has no round 4: its third round (9
    candidates, 14 May 2026; tweaks due 14 Aug 2026; HAWK since withdrawn) runs until the 7th PQC Standardization
    Conference (spring / summer 2027), where NIST decides what to standardise [41]. The "fourth round" so far is the
    main process's for KEMs (2022-2025: BIKE, Classic McEliece, HQC, SIKE). It ended on 11 Mar 2025 with HQC alone
    selected (NIST IR 8545) [42]; NIST planned its draft standard (FIPS 207) about a year later and the final one for
    2027 [44]. Classic
    McEliece was not selected by NIST but became an ISO standard in June 2026 (ISO/IEC 18033-2:2006/Amd 2:2026, with
    ML-KEM and FrodoKEM) [43]. SIKE was broken in 2022. Here: HQC-1/3/5 run in the Pi's TLS sweep and KEM exchange,
    Classic McEliece (5 sets) in the Pi's KEM exchange; BIKE in none (liboqs builds it only on 64-bit hosts; it fails
    in TLS through oqs-provider), and none of them on the Pico yet.

99. [Mac, Pi, Pico] **The pipeline now measures LoRaWAN 1.1 only (7 Oct).** By default, `lorawan11` (the standard,
    AES-128) and `lorawan11_256` (the same 1.1 frame and MIC rules with AES-256 keys), uplink and downlink, on the
    host (`mqtt_bench.AEADS_DEFAULT`) and the Pico (`PIPE[]`: 12 pipeline blocks instead of 60, 41 in all). The
    others stay in the code: `--aeads`, and `-DMT_ALL_SCHEMES` on the Pico. AES-GCM, AES-CCM and Ascon put a 16 B tag
    and their own encryption into the LoRaWAN-shaped frame, which no LoRaWAN network server reads, so `lorawan11_256`
    is the only 256-bit method that keeps LoRaWAN 1.1's own construction.
100. [Pico, Mac] **HQC-1 on the Pico W (7 Oct): fits, through liboqs.** HQC is NIST's code-based KEM (the only one
     selected from the KEM round 4, finding 98); wolfSSL has none, so the KEM-exchange firmware adds it through liboqs
     0.16 (`KEM_hqc_1` in the Pico's liboqs, `kem_wolf.h` with `-DKW_LIBOQS`).
     - The Pico's M0+ code in QEMU (unaligned accesses trapped): keygen 66 M instructions, encapsulation 132 M,
       decapsulation 200 M (about 0.33 / 0.66 / 1.0 s on the Pico), with 52 / 59 / 65 KB of stack and the same secret
       on both sides. pk 2,241 B, ciphertext 4,433 B, secret 32 B.
     - The device keeps keygen and decapsulation, the responder encapsulates. That firmware now runs on an 80 KB
       stack (178 KB of static RAM, 86 KB left for the heap). On the host, the Pico's code agrees with the
       responder's liboqs on all 20 exchanges (`pico/tests/kem_host_test`). Not yet run on a board.
101. [Mac] **The broker's side of the handshake (7 Oct): `broker_hs_timing.c`.** Preloaded into Mosquitto, it times
     the broker's own work per handshake. Mac, loopback, X25519MLKEM768, OpenSSL client, medians of 6:
     ML-DSA-44 TLS 0.86 ms (the client saw 1.11 ms in all): encapsulation 0.10, signing 0.52; mTLS 1.04 ms, with
     0.20 ms to check the client's chain and signature. Ed25519: TLS 0.30 ms (signing 0.03), mTLS 0.53 ms. ML-DSA
     signing varies by handshake (0.24-0.75 ms), as on the clients (finding 5). The broker machine writes
     `results/broker_hs_{raw,summary}_<machine>.csv`, one row per client IP, so Pico and Pi runs stay apart.
102. [Mac] **The reference stage runs the round 3 code (7 Oct).** `setup_round3.sh` fetches and builds SDitH v3
     (NIST package, 12 sets), QR-UOV (NIST package, 15 sets), FAEST 3.0 (faest-ref v3.0.0 through its meson build, 12
     sets) and SQIsign (f417ebd, I / III / V) into `~/.cache/iot-pqc/ref-r3`; all of them now go through
     `bench_template.c` (SQIsign used its own benchmark before, mean only). The round 2 scripts are gone.
     - A smoke run on the Mac (3-5 iterations, medians, keygen / sign / verify): SQIsign-I 11.4 / 32.9 / 4.8 ms,
       III 45 / 132 / 17 ms, V 70 / 200 / 29 ms; SDitH cat1-fast 0.03 / 21.8 / 18.8 ms; QR-UOV 1q127L3 2.5 / 0.45 /
       0.40 ms; FAEST-128f 0.002 / 28.6 / 15.6 ms, EM-128f 0.001 / 23.1 / 11.9 ms. The Pico W's SQIsign-I takes
       about 1,200x the Mac's time (finding 90).

103. [Pico] **What the deployment features cost in flash and RAM (Pico W, built as the runner builds, 7 Oct).** The
     deployment firmware is 672,312 B against 622,760 B for the ML-DSA-44 benchmark firmware (+49.6 KB of the 2 MB
     flash), with 136,376 against 92,264 B of static RAM (+44.1 KB), and it reserves a 64 KB LittleFS partition.
     - The trust anchor itself, the CA certificate (4,005 B for ML-DSA-44), is in every firmware already.
     - The CRL: 2,562 B of data (2,420 B of it the CA's ML-DSA-44 signature; each revoked certificate adds a few
       dozen bytes) and 6,062 B of wolfSSL CRL code; certificate dates and NTP add 1.6 KB. No static RAM: wolfSSL
       parses the CRL onto the heap when it loads it.
     - Keeping an updated trust anchor in flash: LittleFS (25.5 KB of code, the 64 KB partition) and the update key
       (1,312 B). Checking the update reuses the ML-DSA verify that TLS already has.
     - The rest is the test, not what a device needs: the broker's certificate for the signed KEM exchange (4,015 B),
       the old ECDSA root (412 B), the blocks' code (about 6 KB) and their RAM (the update and read-back buffers
       14.3 KB, the KEM exchange's buffers 20.8 KB, two ML-DSA key objects 8.6 KB).
     - Builds made under the scratch folder link LittleFS into every Wi-Fi firmware (arduino-pico links the Wi-Fi
       library's whole dependency chain), 26.6 KB more; the runner's builds in the system temp folder do not.

104. [Mac, Pi, Pico] **The pipeline as a whole, and the same certificates everywhere (8 Oct).**
     - The pipeline now has one whole number per connection, measured on one clock: `whole_first`, from the TCP
       connect through the TLS handshake, MQTT CONNECT and SUBSCRIBE to the first reading verified after its trip
       through the broker (one reading over a fresh post-quantum connection); `whole_all` runs to the last of the N
       readings. Host and Pico W print `whole,iter,first_ms,all_ms,msgs`. Mac, loopback, LoRaWAN 1.1 uplink, 20
       readings, medians: ML-DSA-44 TLS 1.37 ms, mTLS 2.07 ms; Ed25519 TLS 1.15 ms, mTLS 1.49 ms; plain MQTT 0.48 ms.
     - The host's pipeline used to run only the customer's shortlist (ECDSA-P256, ML-DSA-44, Falcon-512), to keep a
       10-scheme run short, while every Pico W certificate firmware runs its pipeline. With LoRaWAN 1.1 only (2
       schemes) the host now runs every TLS certificate too (`SIGS_TLS`); `--sigs` brings back the shortlist.
     - SLH-DSA is skipped in TLS: OpenSSL's TLS layer refuses its certificates, so no TLS / mTLS / pipeline / sweep
       default includes it (its keygen / sign / verify stay in Stage 1 and on the Pico).
105. [Pico] **Round 3 certificates on the Pico W: only SNOVA could work, and only by extending wolfSSL (8 Oct).**
     wolfSSL 5.9.4, the Pico's TLS library, has none of the round 3 schemes and no liboqs bridge. On the broker
     side, OpenSSL with the round 3 oqs-provider serves only MAYO and SNOVA certificates (`certs/round3`); SQIsign,
     QR-UOV, MQOM, FAEST, SDitH and UOV have no TLS support there. MAYO-1's verify needs 225 KB of stack (finding
     95), too much beside TLS on 264 KB. SNOVA fits: small keys and signatures (pk 376 B - 2.7 KB, signature 272 -
     896 B), verify 0.8 s (level I) to 3.5 s (level V) on the Pico, and little stack. Using it means adding SNOVA to
     wolfSSL's certificate parsing and TLS 1.3 signature handling (oqs-provider's OIDs and codepoints, liboqs for
     the maths): a maintained patch to wolfSSL, not a setting. Done in finding 106.
106. [Mac, Pico] **SNOVA certificates in the Pico W's TLS client: wolfSSL's Falcon-512 code carrying SNOVA (8 Oct).**
     - **How.** `make_wolfssl_lib.sh` gives Falcon-512's constants SNOVA's:
       - the OID 1.3.9999.10.<n>.3 and its OID sum;
       - the TLS codepoint 0xFF83 - 0xFF93 (oqs-provider `36cafae` [35]);
       - the key and signature sizes.
     - It also swaps `falcon.c` for `wb_snova.c`, the `wc_falcon_*` calls over liboqs main's SNOVA.
     - wolfSSL's own certificate parsing and TLS 1.3 code for Falcon then carry SNOVA unchanged: 12 constants and
       one file, against about 350 places where wolfSSL handles Falcon. One SNOVA set per firmware
       (`-DWB_SNOVA<set>`); that firmware has no Falcon.
     - **Two wolfSSL limits had to move.**
       - It reads Falcon codepoints by their own first byte (`FALCON_SA_MAJOR`, 0xFE), separately from the
         codepoint it sends.
       - It keeps only 128 bytes of the server's signature-algorithm list, but the round 3 broker offers 80
         algorithms (160 B), so the cut-off list had no SNOVA level V. These builds keep 256 B.
     - **Checked on the Mac** (`pico/tests/snova_tls_host_test`): the Pico's wolfSSL build, compiled natively,
       against the round 3 broker.
       - All 9 sets complete TLS and mTLS and get a CONNACK.
       - A CA key with one bit changed is refused (`ASN sig error, confirm failure`).
       - Single handshakes took 2.5 - 8.7 ms there (a functional check, not a benchmark).
     - **On the M0+** (QEMU, the Pico's own liboqs main library): its SNOVA_I_K verifies the broker's `server.crt`,
       which OpenSSL + oqs-provider signed on the Mac.

       | Set | pk / sig (B) | sign: instructions, stack | verify: instructions, stack |
       |---|---|---|---|
       | I_K | 376 / 528 | 92.3 M, 39.4 KB | 48.8 M, 10.0 KB |
       | I_B | 656 / 388 | 71.8 M, 35.0 KB | 34.5 M, 7.9 KB |
       | I_S | 1016 / 272 | 47.8 M, 26.1 KB | 20.4 M, 6.3 KB |
       | III_K | 912 / 688 | 210.5 M, 59.3 KB | 106.4 M, 11.7 KB |
       | III_B | 1416 / 532 | 173.9 M, 50.9 KB | 83.9 M, 9.6 KB |
       | III_S | 2032 / 456 | 165.3 M, 49.2 KB | 75.3 M, 8.6 KB |
       | V_K | 1216 / 896 | 364.1 M, 92.3 KB | 181.5 M, 17.6 KB |
       | V_B | 1891 / 691 | 299.9 M, 79.1 KB | 140.4 M, 14.1 KB |
       | V_S | 2716 / 591 | 283.8 M, 76.3 KB | 126.1 M, 12.5 KB |

       - None uses the heap. The board's own peaks (2 Oct, the SNOVA rows above) agree.
       - The firmware runs the handshake on that stack + 8 KB (`-DMT_STACK_KB`, 36 - 104 KB).
     - **Firmware (Pico W)** against ML-DSA-44's 622,936 B flash / 92,264 B RAM (built as the runner builds):

       | Set | Flash | RAM (static) |
       |---|---|---|
       | SNOVA_I_S | 690,816 B | 112,912 B |
       | SNOVA_I_K | 699,576 B | 125,200 B |
       | SNOVA_V_K | 725,632 B | 182,544 B |

       68 - 103 KB more flash than ML-DSA-44 (liboqs main's SNOVA in place of wolfSSL's ML-DSA); most of the RAM
       is the stack.
     - **What to expect on the board** (from the 2 Oct sign / verify times at 200 MHz):

       | Level | TLS (two verifies: the chain and CertificateVerify) | mTLS (adds one signature) |
       |---|---|---|
       | I | 1.6 - 2.0 s | 2.6 - 3.3 s |
       | III | 4.4 - 4.6 s | 7.3 - 7.7 s |
       | V | 6.7 - 7.1 s | 11.1 - 12.0 s |

       For comparison, Falcon-512 mTLS took 2.0 s.
     - The firmware fed its 8 s watchdog only while waiting for data. When the server's flight had already
       arrived, level V's two verifies (7.1 s) ran without a feed. It now feeds on every read.
     - **On the board**: SNOVA_I_K, finding 107; all 9 sets, finding 108. There is no sweep in these firmware (`-DMT_NO_SWEEP`): the key-exchange groups
       don't depend on the certificate and were swept with the others.
107. [Pico, Pi] **SNOVA_I_K certificates on the Pico W (8 Oct, broker on the Pi, `pi_broker4`): TLS, mTLS and the
     LoRaWAN 1.1 pipeline all work.** All 15 blocks completed with no errors or watchdog resets; 50 connections per
     mode. Compared with the 2-3 Oct runs on the same Pico W and the same Pi broker (`pi_broker`, `pi_broker2`),
     medians:

     | Certificate | TLS handshake | mTLS handshake | handshake down (TLS) / up (mTLS) | wolfSSL peak heap TLS / mTLS |
     |---|---|---|---|---|
     | SNOVA_I_K | 2,250 ms | 3,622 ms | 3,051 / 3,159 B | 22.0 / 23.7 KB |
     | ML-DSA-44 | 283 ms | 511 ms | 7,780 / 7,890 B | 28.1 / 39.0 KB |
     | Falcon-512 | 233 ms | 1,245 ms | 3,822 / 3,934 B | 22.2 / 76.0 KB |
     | ECDSA-P256 | 395 ms | 460 ms | 1,838 / 1,942 B | 21.4 / 22.0 KB |
     | RSA-3072 | 361 ms | 3,632 ms | 2,800 / 2,916 B | 22.0 / 26.4 KB |

     - **SNOVA's maths is the handshake.** In TLS the two verifies (the chain and CertificateVerify) take 2,028 ms,
       1,014 ms each (90 % of the handshake); the ML-KEM / X25519 key share 66 + 70 ms. mTLS adds the signature,
       1,355 ms. Both are within 2 % of the bare sign / verify on this board (2 Oct: 1,334 / 991 ms), so the wolfSSL
       glue (`wb_snova.c`) costs next to nothing.
     - **TLS is steady (standard deviation 14 ms), mTLS less so (321 ms).** 47 of 50 signatures took 1,352-1,365 ms; the other 3
       took 2,694-2,702 ms, twice as long: SNOVA draws new values and solves again when its linear system has no
       solution.
     - **Smallest post-quantum handshake on the wire, lowest post-quantum heap.** SNOVA_I_K's 376 B public key and
       528 B signature make its certificates 1,167 / 1,175 B, so a TLS handshake receives 3,051 B (ML-DSA-44 7,780 B).
       Its heap stays at 22-24 KB, where Falcon-512 signing needs 76 KB. The cost is the stack: 40.5 KB in mTLS,
       12.2 KB in TLS (QEMU: 39.4 and 10.0 KB for SNOVA alone), in a 48 KB stack. The free heap stayed flat
       across all 50 connections (no leak).
     - **Server-auth TLS is about 8x ML-DSA-44's; mTLS matches RSA-3072's** (3.6 s, which is RSA-3072's signing).
     - **The pipeline as a whole:** from the TCP connect to the first LoRaWAN 1.1 reading verified (`whole_first`),
       2.28 s over TLS and 3.68 s over mTLS, against 25-42 ms over plain MQTT. After that, a reading takes the same
       as with any certificate: seal 0.43-0.95 ms, open 0.60-1.09 ms (AES-128 / AES-256, uplink / downlink), broker
       round trip 6.3-6.6 ms (4.3-4.7 ms plain), 112 B per message (90 B plain).
108. [Pico, Pi] **All 9 SNOVA sets on the Pico W (8 Oct, Pi broker, `pi_broker4`).** 50 connections per mode and 4
     pipeline connections per block, LoRaWAN 1.1. Medians (ms; bytes; KB = 1,000 B for the heap, 1,024 for the stack):

     | Set | TLS | mTLS | verify x2 / sign | `whole_first` TLS / mTLS | down (TLS) / up (mTLS) | heap TLS / mTLS | stack TLS / mTLS |
     |---|---|---|---|---|---|---|---|
     | I_K | 2,250 | 3,622 | 2,028 / 1,355 | 2,281 / 3,680 | 3,051 / 3,159 | 22.0 / 23.7 | 12.2 / 40.5 |
     | I_B | 1,965 | 3,133 | 1,750 / 1,156 | 2,008 / 3,192 | 3,051 / 3,159 | 22.2 / 24.4 | 10.1 / 36.2 |
     | I_S | 1,846 | 2,876 | 1,635 / 1,015 | 1,900 / 2,935 | 3,179 / 3,287 | 22.6 / 25.3 | 8.5 / 27.3 |
     | III_K | 4,904 | 8,032 | 4,665 / 3,113 | 4,998 / 8,135 | 3,907 / 4,015 | 22.5 / 25.4 | 13.3 / 60.5 |
     | III_B | 4,758 | 7,684 | 4,521 / 2,921 | 4,845 / 7,786 | 4,099 / 4,207 | 23.0 / 26.8 | 11.2 / 52.1 |
     | III_S | 4,794 | 7,697 | 4,555 / 2,910 | 4,902 / 7,824 | 4,563 / 4,671 | 23.6 / 28.6 | 10.2 / 50.4 |
     | V_K | 7,479 | 12,418 | 7,221 / 4,949 | 7,557 / 12,584 | 4,627 / 4,735 | 22.8 / 26.6 | 19.2 / 93.5 |
     | V_B | 7,082 | 11,645 | 6,852 / 4,561 | 7,190 / 11,787 | 4,892 / 5,000 | 23.5 / 28.4 | 15.9 / 80.4 |
     | V_S | 7,078 | 11,608 | 6,855 / 4,520 | 7,182 / 11,729 | 5,517 / 5,625 | 24.3 / 30.7 | 14.1 / 77.6 |

     Level V is the second run, with the watchdog fed during signing (below); levels I and III the first.

     - **Every set works in TLS, mTLS and the pipeline.** The handshake is SNOVA's maths: verifying is 90-97 % of a
       TLS handshake, and each verify / signature is within 1-3 % of the bare times on this board (2 Oct), so the
       wolfSSL glue costs nothing measurable. Level I's S set is the fastest SNOVA (TLS 1.85 s, mTLS 2.88 s: 6.5x and
       5.9x ML-DSA-44's 286 / 484 ms on the same day); level III roughly 2.5x level I, level V roughly 4x.
     - **Even level V puts fewer bytes on the wire than ML-DSA-44** (TLS, down: 4.6-5.5 KB against 7.8 KB). The heap
       stays at 22-31 KB at every level (ML-DSA-44 28 / 39 KB, Falcon-512 22 / 76 KB). The stack is the cost:
       27-94 KB in mTLS, each set's QEMU signing peak + 1.2-1.3 KB, inside the stack each firmware got (36-104 KB;
       V_K 93.5 of 104 KB).
     - **6 % of signatures retry** (27 of 450: 14 of 300 at levels I and III, 13 of 150 at level V). SNOVA starts over
       when its linear system has no solution, so each retry adds exactly one more signature's time; one V_K signature
       retried twice (14.8 s). This is where mTLS's spread comes from (TLS: 7-27 ms standard deviation).
     - **Level V mTLS first lost its connect blocks to the watchdog.** One level V signature is 4.4-4.9 s; a retry makes it
       9-10 s, and the firmware's 8 s watchdog (the RP2040's longest) cannot be fed inside the liboqs call. V_K and
       V_S hung during their warm-up connections, V_B after 21; the pipeline blocks (4 connections each) mostly got
       through, so level V's `whole_first` mTLS numbers stand. Fixed: `wb_snova.c` now calls `wb_snova_sign_begin()` /
       `_end()` around each signature (weak, empty on a host), and `mqtt_tls_bench` fills them with a timer that feeds
       the watchdog every 2 s during the signature, at most 10 times (20 s), so a real hang still resets the board.
       Tested: compiles (V_K: the sketch's hooks, not the empty defaults, are linked), the host test still passes
       (SNOVA5K TLS / mTLS), and on the board (second level V run, 8 Oct): 50 of 50 mTLS connections per set, no
       watchdog reset, through signatures of up to 14.8 s.
109. [Pico, Pi] **The four deployment items on the Pico W (8 Oct, Pi broker): all passed, the first board run.**
     - **Hostname, CRL, dates (NTP):** the wrong broker IP refused (`peer ip address mismatch`), `revoked.crt` refused
       (`CRL Cert revoked`), `expired.crt` refused (`ASN date error`, against NTP time). 20 connections each: TLS
       282 ms with or without the checks. wolfSSL verifies the CRL's own ML-DSA-44 signature once, when the firmware
       loads it into the block's TLS context (`wolfSSL_CTX_LoadCRLBuffer`, before the connections); a handshake then
       only looks the server certificate's serial up (`CheckCertCRL`). That one verify (~27 ms, wolfSSL's ML-DSA-44 on
       this board) is in no timed number. mTLS 494 ms unchecked against 403 ms
       checked: the difference is ML-DSA-44's signing (148 vs 52 ms median, rejection sampling, finding 88), not the
       checks.
     - **Signed trust-anchor update:** the old (ECDSA-P256) root couldn't reach the broker (`ASN no signer`); the
       6,429 B update came off the broker in 35 ms, verified (ML-DSA-44) in 33 ms, a changed byte was refused, flash
       write 48 ms, read back 1.2 ms; then the broker was reached under the new root (TLS 290 ms).
     - **FCnt across a reboot:** 200 frames with FCnt reserved 64 ahead: 3 flash saves, 4.1 ms median (37 ms the
       first, which creates the file). After the board's own reboot it went on from the reservation (256 after 200),
       same DevAddr: no FCnt reused.
     - **KEM exchange plain / over mTLS / signed (ML-DSA-44 both ways), 50 each:** ML-KEM-768 31 / 38 / 51 ms,
       X25519MLKEM768 152 / 159 / 164 ms. mTLS adds 7 ms, signing both messages 13-20 ms more.
     - The host side on the Pi: finding 111.
110. [Pico, Pi] **The 9 certificates again, with their first whole-pipeline numbers, and the KEM firmware (8 Oct, Pi
     broker).**
     - TLS reproduces 3 Oct within 0-3 % for all 9 (229-413 ms). mTLS too, except ML-DSA (signing by rejection
       sampling: ML-DSA-65 633 vs 772 ms, ML-DSA-87 879 vs 791 ms). RSA-3072's mTLS connect block stopped after 25
       connections: the board hung in TCP connect (the Wi-Fi stall, finding 75).
     - **`whole_first` on the Pico W** (TCP connect to the first LoRaWAN 1.1 reading verified, medians of 4 blocks):

       | Certificate | TLS | mTLS |
       |---|---|---|
       | Falcon-512 | 269 ms | 1,304 ms |
       | Falcon-1024 | 301 ms | 2,583 ms |
       | RSA-2048 | 313 ms | 1,317 ms |
       | ML-DSA-44 | 325 ms | 523 ms |
       | ML-DSA-65 | 378 ms | 715 ms |
       | Ed25519 | 390 ms | 450 ms |
       | RSA-3072 | 396 ms | 3,762 ms |
       | ECDSA-P256 | 441 ms | 497 ms |
       | ML-DSA-87 | 449 ms | 1,029 ms |

       Plain MQTT: 32-39 ms. The handshake is 85-97 % of it; over TLS the rest (TCP connect, MQTT CONNECT, SUBSCRIBE,
       the reading's trip through the broker) is 39-44 ms, the same work as plain MQTT's.
     - The sweep lost the same blocks as on 3 Oct: the two ML-KEM-512 hybrids (codepoints, finding 85) and
       `p384_mlkem768` right after them (finding 88). Not in the current focus.
     - **HQC-1 on the board (the KEM firmware):** key pair 505 ms, decapsulation 1,543 ms (64.8 KB of stack, inside
       the 80 KB), the whole exchange 2.09 s with a 2,241 B public key and a 4,433 B ciphertext; ML-KEM-768 takes
       31.9 ms. The X25519 A/B repeats 1 Oct: wolfSSL's small Curve25519 code 424 ms per operation, its normal code
       57 ms.
111. [Pi, Mac] **The deployment checks from the Pi 4, against the Mac broker over the LAN (8 Oct): all passed.**
     The Pi as the OpenSSL client (`./run_all.sh --only deploy --broker <Mac>`), 50 connections or exchanges each.
     - **Refused, as they must be:** the wrong broker IP (`IP address mismatch`), `revoked.crt` (`certificate
       revoked`), `expired.crt` (`certificate has expired`).
     - **The checks are nearly free:** TLS 13.4 ms, 14.1 ms with the name and CRL checks (+0.76 ms). The client's
       verify time grows from 1,072 to 1,556 us with the same 2 calls: OpenSSL checks the CRL's own ML-DSA-44 signature
       inside `X509_verify_cert`, in every checked handshake (+0.48 ms, one ML-DSA-44 verify on the Pi 4). mTLS 21.0 ms
       unchecked against 17.3 ms checked is not the checks: the unchecked block ran slower in all its crypto (key share
       666 vs 394 us, completion 903 vs 513 us, signing 3.5 vs 2.2 ms), so the Pi 4 was busier during it, on top of
       ML-DSA-44's signing spread (0.9-7.1 ms, rejection sampling). Handshake bytes: 1,568 up / 7,823 down (TLS),
       8,076 / 8,032 (mTLS).
     - **KEM exchange plain / over mTLS / signed:** ML-KEM-768 6.3 / 7.6 / 9.5 ms, X25519MLKEM768 8.2 / 8.2 / 10.2 ms.
       The Pi's own crypto is small: ML-KEM-768 key pair 62 us, decapsulation 81 us; X25519MLKEM768 207 / 482 us;
       ML-DSA-44 signing 1.3-2.1 ms median, verifying 0.48 ms. The round trip through the broker and its responder
       (6-9 ms) is most of each exchange. The Pico W's ML-KEM-768 exchange is 31 ms (finding 109): its key pair and
       decapsulation (11 + 14 ms) take most of it.
     - With finding 109 (the Pico W) and finding 97 (the Mac) every part of the four deployment items has run where it
       applies: the trust-anchor update and FCnt are the device's (the broker only publishes the update).

112. [Mac, Pico] **Both CRL checks built (8 Oct): the host wolfSSL client, and every certificate type.**
     - **The host wolfSSL client checks the CRL now.** Its build gains `--enable-crl` and `--enable-ip-alt-name`; the
       second was missing too, so it could not match an IP address in a certificate's names (a checked connection by
       IP failed: `peer ip address mismatch`). `CHECK_CRL` → `wolfSSL_CTX_EnableCRL` + `wolfSSL_CTX_LoadCRLFile`: the
       CRL's signature is checked once, at load (OpenSSL checks it in every handshake).
     - The Mac's `mqtt_tls_timer_wolfssl` dated from 28 Sep, before `CHECK_HOST`: `build_wolfssl.sh` rebuilds the
       library, `build_timer.sh wolfssl` relinks the client. Rebuilt; the Pi builds its own.
     - **Every certificate type gets the deployment checks.** `DEPLOY_SIGS=all gen_certs.sh --deploy <IP>...` makes
       `certs/DEPLOY_<SIG>` for the other 8 types next to DEPLOY (ML-DSA-44), each with its own CA, ClientCA, CRL and
       revoked / expired certificates; the broker serves each set present on four listeners. Each CRL is signed with
       its CA's algorithm, so its size is mostly that signature:

       | CA | CRL | CA | CRL | CA | CRL |
       |---|---|---|---|---|---|
       | Ed25519 | 199 B | RSA-3072 | 539 B | ML-DSA-44 | 2,562 B |
       | ECDSA-P256 | 218 B | Falcon-512 | 799 B | ML-DSA-65 | 3,459 B |
       | RSA-2048 | 411 B | Falcon-1024 | 1,418 B | ML-DSA-87 | 4,777 B |

     - **Tested on the Mac** (`mqtt_bench.py --role both --deploy`, a local broker, 5 connections per mode, both
       clients): in all 9 sets the checked connections succeed and both clients refuse the wrong IP, the revoked and
       the expired certificate (OpenSSL: `IP address mismatch`, `certificate revoked`, `certificate has expired`;
       wolfSSL: `peer ip address mismatch`, `CRL Cert revoked`, `ASN date error`): 72 connect blocks OK, 54 of 54
       refused.
     - **Pico:** `-DMT_DEPLOY_CHECKS` builds the connect and refuse blocks (7) for any certificate type; all 8 compile
       (601-659 KB flash, 92 KB RAM; the full ML-DSA-44 firmware 672,592 B). Each refuse line now carries
       `crl_load_us`, the time wolfSSL takes to load and verify the CRL, and `crl_B`. Expected from the board's own
       verify times: Falcon-512 7 ms, RSA-2048 26 ms, ML-DSA-44 27 ms, Ed25519 66 ms, ML-DSA-87 74 ms, ECDSA-P256 96 ms.
       Not run on the board yet.

113. [Pico, Pi] **The CRL checks for each certificate type on the Pico W (8 Oct, Pi broker): 8 of 9 sets.** Falcon-512
     didn't start: the board got no time from `pool.ntp.org` within 30 s (`#fatal NTP`), so it runs again. In every
     other set the checked connections succeed and the wrong IP, the revoked and the expired certificate are refused.
     - **The CRL costs one signature check in the CA's algorithm, once per load.** `crl_load_us` (median of the three
       refuse blocks) against the board's own verify time for that algorithm (Stage 1, wolfSSL):

       | CA | CRL | Load + verify | Verify alone |
       |---|---|---|---|
       | Falcon-1024 | 1,419 B | 15.5 ms | 14.4 ms |
       | RSA-2048 | 411 B | 27.1 ms | 25.7 ms |
       | ML-DSA-44 | 2,562 B | 29.5 ms | 27.1 ms |
       | ML-DSA-65 | 3,459 B | 46.2 ms | 44.8 ms |
       | RSA-3072 | 539 B | 59.3 ms | - |
       | ML-DSA-87 | 4,777 B | 75.6 ms | 74.1 ms |
       | Ed25519 | 199 B | 76.2 ms | 65.5 ms |
       | ECDSA-P256 | 218 B | 98.4 ms | 95.7 ms |

       Parsing adds 1-3 ms (10 ms for Ed25519); the size hardly matters. The classical CAs are the slowest to check
       here: the Pico verifies ECDSA-P256 and Ed25519 slower than ML-DSA or Falcon.
     - **Per handshake the checks cost nothing on the Pico, for any type**: TLS with vs without them -4.4 to +2.9 ms in
       7 sets, with identical verify times; RSA-3072 +21 ms with identical verify times too (run to run).
     - Not run yet: Falcon-512 again, and the Pi 4's host side (both clients) against the Mac broker.

114. [Pi, Pico] **The CRL checks on every certificate type, done (9 Oct): Falcon-512 on the Pico W, and the Pi 4 against
     the Mac broker with both clients.**
     - **Pico W, Falcon-512** (after the NTP timeout): all three refused, CRL (798 B) loaded and verified in 8.2 ms, TLS
       231 ms unchecked / 233 ms checked. With finding 113, all 9 types on the Pico: one CA-signature check per load,
       8-98 ms, and nothing per handshake.
     - **Pi 4: 54 of 54 bad connections refused** (OpenSSL and wolfSSL, 9 sets x wrong IP / revoked / expired); all 72
       connect blocks OK.
     - **What a checked handshake costs on the Pi 4**, as the client's verify time (more stable than the handshake over
       the LAN, which moves by 1-3 ms between blocks):

       | CA | OpenSSL: + per handshake | wolfSSL: + per handshake |
       |---|---|---|
       | RSA-2048 | +0.19 ms | +0.00 ms |
       | Ed25519 | +0.31 ms | +0.00 ms |
       | RSA-3072 | +0.32 ms | +0.03 ms |
       | ECDSA-P256 | +0.34 ms | +0.01 ms |
       | ML-DSA-44 | +0.53 ms (fastest connection; that block ran slower) | +0.02 ms |
       | ML-DSA-65 | +0.71 ms | +0.01 ms (fastest; that block ran slower) |
       | ML-DSA-87 | +1.09 ms | +0.01 ms |
       | Falcon-512 | +1.13 ms | +0.00 ms |
       | Falcon-1024 | +1.28 ms | +0.00 ms (fastest; that block ran slower) |

       OpenSSL checks the CRL's signature in every handshake, wolfSSL once when it loads the CRL, so its handshakes
       don't pay for it. Through oqs-provider, a Falcon CRL check costs OpenSSL more than an ML-DSA one.
     - Three blocks ran slower in all their crypto (the key share 1.8-2x), so the Pi 4 itself was busy then; for those
       the fastest connection is compared.

115. [Pi, Mac] **ChirpStack accepts our LoRaWAN 1.1 uplinks: a simulated network with no radio (9 Oct, branch
     `LoRa_1.1_implementation`).**
     - **Path:** Pi 4: `network/virtual_gateway.py` (Semtech UDP, reports channel 0 at DR0) → ChirpStack Gateway Bridge 4
       (Docker, `scripts/setup_gateway_pi.sh`) → MQTT over the LAN → Mac: ChirpStack 4 (chirpstack-docker), region
       AS923, one ABP device with MAC version 1.1.0.
     - **Frames:** three LoRaWAN 1.1 uplinks sealed by `app_aead.c` (`lorawan11`, AES-128; the pipeline's 51-byte
       reading; FCnt 1-3; test keys, `docs/pending.md` step 3).
     - **Result:** ChirpStack checked the MIC and decrypted each frame: up events for FCnt 1, 2 and 3 at DR 0, with data
       `{"seq":n,"temp_c":21.5,"rh":48}` plus padding, byte for byte. This is the first check of our 1.1 uplink by
       another implementation: the self-test's published vectors cover a 1.0 uplink and a 1.1 downlink MIC only. So
       the B1 block (TxDr = TxCh = 0), both CMACs and the AES-128-CTR payload agree with ChirpStack's.
     - **Frames sent close together are dropped.** Sent within 1 ms, FCnt 2 and 3 were accepted and FCnt 1 dropped.
       ChirpStack holds each uplink ~200 ms for copies from other gateways, then handles them in parallel, and a frame
       below the stored counter counts as old. Its downlinks were timed exactly 1 s (RX1) after FCnt 2 and FCnt 3, and
       both used downlink counter 0. A real device can't send this fast (an SF12 frame is ~2.8 s on air), so the
       virtual gateway now spaces frames (`--gap`, 1 s); with it, FCnt 1 was accepted after re-activation.
     - **Its downlinks** were DevStatusReq (MAC command 0x06, decrypted with NwkSEncKey): ChirpStack asks for battery
       and link margin, per the device profile's device-status request frequency. With no radio, set it to 0.
     - **Not yet:** our live pipeline through ChirpStack, the AES-256 inner layer, ChirpStack's TLS links and its delay
       (`docs/pending.md` steps 4-10): findings 116-117. Versions: ChirpStack 4.19.2 (image `sha256:cecb45bd…`), Gateway
       Bridge image `sha256:cc820a19…` (tag `4`), Mosquitto 2.1.2 (eclipse-mosquitto:2).

116. [Mac, one machine] **The pipeline through ChirpStack, both ways, with the AES-256 layer only the application
     removes (9 Oct, branch `LoRa_1.1_implementation`).**
     - **Path:** the host client as one fixed device (`DEV_ADDR=01234567`, FCnt kept in a file) → our Mosquitto →
       watcher (`RAW=1`) → `virtual_gateway.py` → a Gateway Bridge container → ChirpStack 4.19.2 → its event over MQTT →
       `chirpstack_app.py`. All on the Mac (plain MQTT for our hop): a functional check, not a two-machine result.
     - **`lorawan11_e2e`, new scheme:** the standard 1.1 frame (AES-128 encryption and MIC, FPort 2) around AES-256-CTR
       under a 32-byte key ChirpStack never holds. ChirpStack accepted `lorawan11` FCnt 11-13 and `lorawan11_e2e` FCnt
       75-77, all six readings in order. For the e2e frames it forwarded only the inner ciphertext; the application
       decrypted it to `{"seq":n,...}`. Host and Pico code give identical frames (`aead_host_test`, 88 / 88), and the
       application's decryption (the `openssl` command) recovers a reading from a frame the C code sealed. No extra
       bytes: the frame is 64 B as for `lorawan11`.
     - **Downlinks:** a downlink queued in ChirpStack went out after the device's next uplink (Class A), through the
       bridge and the virtual gateway, and the relay (`PUB=pqc/down`) published it on `pqc/down/01234567`; the device's
       watcher verified its LoRaWAN 1.1 downlink MIC and decrypted "hello device". With finding 115, ChirpStack has now
       checked our 1.1 uplink and downlink code both ways.
     - **ChirpStack's delay** (frame handed to the bridge → event at the application, same clock, 10 frames each):
       median 220.3 ms, p95 227.1 ms at its default de-duplication wait (200 ms); median 29.5 ms, p95 37.1 ms at
       `deduplication_delay="10ms"`. The wait for copies from other gateways is most of it; about 20-30 ms is
       ChirpStack and the MQTT hops on one machine. The Pi ↔ Mac measurement is `docs/pending.md` step 10.

117. [Mac, Docker] **ChirpStack's own MQTT clients can't do PQ TLS; the Gateway Bridge does the hybrid key exchange
     only (9 Oct, `scripts/chirpstack_tls_test.sh`).** Our Mosquitto 2.1.2 (OpenSSL 3.6.4) in seven set-ups; our own
     client (OpenSSL) passed all seven, so the brokers were right:

     | Set-up | Gateway Bridge (Go `crypto/tls`) | ChirpStack 4.19.2 (rustls 0.23, `ring`) |
     |---|---|---|
     | X25519, ECDSA P-256 certificate | pass | pass |
     | X25519MLKEM768 only, ECDSA certificate | **pass** | fail: broker "no suitable key share" |
     | X25519MLKEM768 only, ML-DSA-44 server certificate | fail: broker "no suitable signature algorithm" | fail (key share) |
     | X25519MLKEM768 only, ML-DSA-44 mTLS | fail: can't load the key ("failed to parse private key") | fail: "failed to parse private key as RSA, ECDSA, or EdDSA" |
     | X25519MLKEM768 only, ECDSA mTLS (mixed) | **pass** | fail (key share) |
     | X25519, ML-DSA-44 server certificate | fail: "no suitable signature algorithm" | fail: "no suitable signature algorithm" |
     | X25519, ML-DSA-44 mTLS | fail: can't load the key | fail: can't load the key |

     - The bridge (gateway → network server) gets the PQ key exchange with classical certificates: the mixed set-up.
     - ChirpStack (network server → its broker, and to the application) has neither: its `ring` provider offers no
       ML-KEM group and verifies no ML-DSA signature. Its events, the readings in clear for `lorawan11`, would cross
       that link under classical TLS only; `lorawan11_e2e` keeps the reading itself encrypted with AES-256.
     - Options (not built): a TLS proxy on OpenSSL 3.5+ next to ChirpStack; ChirpStack built with rustls' `aws-lc-rs`
       provider (hybrid key exchange); PQ certificates wait for both libraries.

118. [Mac, one machine] **PQ TLS on every network link of the ChirpStack chain, through stunnel, and the device on a
     UDP "air" (9 Oct, branch `LoRa_1.1_implementation`).** One broker for both sides of ChirpStack here; finding 119
     has the layout the project uses (a separate MQTT broker after ChirpStack).
     - **Chain:** device (`mqtt_tls_timer AIR=1`: one UDP datagram per LoRaWAN frame, no broker, as a radio) →
       `virtual_gateway.py --air` → Gateway Bridge → stunnel → **TLS 1.3, X25519MLKEM768, ML-DSA-44 mTLS** →
       ChirpStack's Mosquitto (OpenSSL 3.5.8, listener 8883) ← the same ← stunnel ← ChirpStack; Mosquitto → the same →
       the application. The Gateway Bridge and ChirpStack speak plain MQTT only to their own stunnel (loopback / the
       compose network); the gateway side ran from the Pi script's configs (`setup_gateway_pi.sh`, `DRY=1`).
     - **The broker refuses the rest:** an X25519-only client (handshake failure) and a client without a certificate
       ("certificate required"); `openssl s_client` with the application's certificate negotiated X25519MLKEM768.
       ChirpStack's 16 MQTT connections (its integration and one per region) went through its stunnel with no TLS error.
     - **Result:** `lorawan11` FCnt 459-461 and `lorawan11_e2e` FCnt 523-525 read by the application in order, the e2e
       ones decrypted only there. A downlink queued in ChirpStack went out after the next uplink, back over the air to
       the device's socket; the device verified its 1.1 MIC and decrypted "hello over the air".
     - **Delay** (frame to the bridge → event at the application): median 219.6 ms, p95 220.9 ms over 6 frames, the same
       as plain MQTT (220.3 ms, finding 116). The PQ handshakes happen once per long-lived MQTT connection, not per
       message. The Pi ↔ Mac run is `docs/pending.md`.
     - The Pico's ChirpStack firmware sends each uplink to the air too (`AIR=` at build time; compiled, not run).

119. [Mac + Pi] **The required chain: gateway → stunnel → ChirpStack → stunnel → MQTT broker → application, PQ on
     both sides of ChirpStack (9 Oct, branch `LoRa_1.1_implementation`).**
     - **Layout:** the gateway's stunnel ends at ChirpStack's own Mosquitto (:8883; ChirpStack takes gateway traffic only
       from a broker, which it reads inside its Docker network). ChirpStack's MQTT integration goes through a second
       stunnel to the project's PQ MQTT broker (the benchmark broker's ML-DSA-44 mTLS listener, :18835, certs/MLDSA44),
       where the application subscribes. Every network hop: TLS 1.3, X25519MLKEM768, ML-DSA-44 client certificates.
     - **On the Mac** (the project broker run there in the Pi's place): `lorawan11` FCnt 587-589 and `lorawan11_e2e`
       FCnt 651-653 reached the application in order; the e2e readings decrypted only there. The application published a
       downlink command on the MQTT broker with its ML-DSA certificate; ChirpStack sent it after the next uplink, back
       through its stunnel, the gateway and the air, and the device verified it ("queued via the PQ MQTT broker").
       ChirpStack's delay: median 224.5 ms, p95 227.7 ms over 6 frames (one more broker hop than 118's 219.6 ms).
     - **With the Pi's broker:** ChirpStack's stunnel then connected to the Pi's `--serve-broker` (192.168.50.132:18835)
       with no TLS or MQTT error: the two machines share the ML-DSA-44 CA. The gateway side on the Pi and a run
       through it are still to do (`docs/pending.md`).
     - The benchmark set's server certificate names only localhost / 127.0.0.1, so ChirpStack's stunnel checks the CA
       but not the broker's address (stunnel warns); a certificate naming the Pi's address would add that check.

### Sources

All links checked on 28 Sep 2026.

**LoRaWAN**

1. LoRa Alliance, *LoRaWAN L2 1.0.4 Specification* (2020): FRMPayload encryption, MIC, OTAA join, 32-bit counters. <https://lora-alliance.org/wp-content/uploads/2021/11/LoRaWAN-Link-Layer-Specification-v1.0.4.pdf>
2. The Things Network, *What's new in LoRaWAN 1.0.4*: DevNonce counter, 32-bit FCnt, JoinEUI / JoinNonce names. <https://www.thethingsnetwork.org/article/whats-new-in-lorawan-104-1>
3. LoRa Alliance, *Technical Recommendations for Preventing State Synchronization Issues around LoRaWAN 1.0.x Join Procedure* (2020): JoinNonce counter check. <https://lora-alliance.org/wp-content/uploads/2020/11/lorawan-1.0.x-join-synch-issues-remedies-v1.0.0.pdf>
4. Semtech, LoRaMac-node, `src/mac/LoRaMacCrypto.c` / `.h`: reference 1.0.x / 1.1 crypto; `USE_RANDOM_DEV_NONCE`, `USE_10X_JOIN_NONCE_COUNTER_CHECK`. <https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/LoRaMacCrypto.c>
5. lora-packet: the uplink vector in its README, and the join / session-key vectors in `__tests__/`. <https://github.com/anthonykirby/lora-packet>
6. brocaar/lorawan (ChirpStack): the 1.1 Join-Accept vector and the 1.1 downlink MIC vector ("Mac-commands in FOpts (encrypted, using AFCntDown encryption flag)") in `phypayload_test.go`. <https://github.com/brocaar/lorawan>

**Standards**

7. RFC 4493, *The AES-CMAC Algorithm*, with test vectors. <https://www.rfc-editor.org/rfc/rfc4493>
8. NIST SP 800-232, *Ascon-Based Lightweight Cryptography Standards* (Ascon-AEAD128). <https://csrc.nist.gov/pubs/sp/800/232/final>
9. ascon-c, the reference and optimised C / assembler implementations (`opt64`, `armv6m_lowsize`). <https://github.com/ascon/ascon-c>
10. FIPS 203, ML-KEM. <https://csrc.nist.gov/pubs/fips/203/final>
11. FIPS 204, ML-DSA. <https://csrc.nist.gov/pubs/fips/204/final>
12. FIPS 205, SLH-DSA. <https://csrc.nist.gov/pubs/fips/205/final>
13. IETF draft-ietf-tls-ecdhe-mlkem: X25519MLKEM768 for TLS 1.3. <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
14. NIST IR 8545: fourth-round report, HQC selected. <https://csrc.nist.gov/pubs/ir/8545/final>
15. NIST, *Additional Digital Signature Schemes, Round 2* (the on-ramp candidates). <https://csrc.nist.gov/projects/pqc-dig-sig/round-2-additional-signatures>
16. *Benchmarking NIST-Standardised ML-KEM and ML-DSA on ARM Cortex-M0+: Latency, Rejection-Sampling Variance, and Memory on the RP2040*, arXiv:2603.19340. <https://arxiv.org/abs/2603.19340>

**Libraries and tools**

17. liboqs (0.16.0 release notes: "SPHINCS+ was removed in 0.16.0"; `OQS_EMBEDDED_BUILD`). <https://github.com/open-quantum-safe/liboqs>
18. oqs-provider. <https://github.com/open-quantum-safe/oqs-provider>
19. OpenSSL 3.5 NEWS: "Support for PQC algorithms (ML-KEM, ML-DSA and SLH-DSA)". <https://github.com/openssl/openssl/blob/openssl-3.5/NEWS.md>
20. wolfSSL (5.9.4; the first results used 5.9.2): ML-DSA, SLH-DSA, ML-KEM; Ascon behind `--enable-experimental`. <https://github.com/wolfSSL/wolfssl>
21. Eclipse Mosquitto. <https://mosquitto.org/>
22. PQClean (`clean` implementations; pqcrypto wraps it). <https://github.com/PQClean/PQClean>
23. mldsa-native (the ML-DSA code in liboqs and in `mldsa_bench`). <https://github.com/pq-code-package/mldsa-native>
24. pqm4: Cortex-M4 assembler PQC implementations. <https://github.com/mupq/pqm4>
25. Mbed TLS / TF-PSA-Crypto roadmap. <https://mbed-tls.readthedocs.io/en/latest/project/roadmap/>
26. BearSSL, constant-time crypto (`aes_ct`). <https://bearssl.org/constanttime.html>
27. XKCP, the eXtended Keccak Code Package (ARMv6-M / ARMv7-M Keccak assembler, CC0). <https://github.com/XKCP/XKCP>
28. Raspberry Pi, *RP2040 Datasheet* (Cortex-M0+, no crypto hardware). <https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf>
29. Raspberry Pi, *RP2350 Datasheet* and product page: Cortex-M33 with single-precision FPU and DSP instructions, a hardware SHA-256 accelerator, no AES accelerator listed. <https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf>, <https://www.raspberrypi.com/products/rp2350/>
30. arduino-pico (Earle Philhower core; 6.1.1 pinned, 5.6.0 before 28 Sep). <https://github.com/earlephilhower/arduino-pico>
31. lora-rs issue #335, *LoRaWAN 1.0.4 support (DevNonce storage)*. <https://github.com/lora-rs/lora-rs/issues/335>

**Round 3 (liboqs main / oqs-provider)**

32. liboqs PR #2562, *Update SNOVA to Round 3*. <https://github.com/open-quantum-safe/liboqs/pull/2562>
33. liboqs PR #2564, *Update to MAYO round 3*. <https://github.com/open-quantum-safe/liboqs/pull/2564>
34. liboqs commit `e128800`, *Integrate MQOM v3 (NIST round 3 version), and remove MQOM v2* (9 Sep 2026). <https://github.com/open-quantum-safe/liboqs/commit/e1288004212cc2b7a3421231ef6731eeda70a659>
35. oqs-provider PR #830, *Update MAYO, MQOM and SNOVA to round-3 variants* (`36cafae`, 19 Sep 2026). <https://github.com/open-quantum-safe/oqs-provider/pull/830>
36. T. Reddy et al., *Use of SLH-DSA in TLS 1.3*, IETF draft `draft-reddy-tls-slhdsa-02` (SLH-DSA signature codepoints). <https://datatracker.ietf.org/doc/draft-reddy-tls-slhdsa/>
37. NIST, *Round 3 Additional Signatures* (candidates, submission packages, HAWK's withdrawal). <https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures>
38. PostQuantum.com, *NIST Selects 9 Third-Round PQC Signature Candidates* (the five eliminated, the 14 Aug 2026 tweak deadline, SNOVA and the wedge attack). <https://postquantum.com/security-pqc/nist-third-round-pqc-signatures/>
39. freenode, *NIST locks FN-DSA to fixed-point math for FIPS 206* (28 Sep 2026: 32.32 key generation, 64.64 signing, one KAT-testable signing procedure). <https://freenode.net/article/nist-locks-fn-dsa-to-fixed-point-math-for-fips-206>
40. R. Perlner, *FIPS 206 Status Update*, NIST, 6th PQC Standardization Conference (2025). <https://csrc.nist.gov/csrc/media/Presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf>
41. Quantum Computing Report, *NIST Advances Nine Post-Quantum Digital Signature Candidates to Third Evaluation Round* (two-year round, decisions at the 7th PQC Standardization Conference, tweaks by 14 Aug 2026). <https://quantumcomputingreport.com/nist-advances-nine-post-quantum-digital-signature-candidates-to-third-evaluation-round/>
42. NIST, *Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process*, NIST IR 8545 (11 Mar 2025). <https://www.nist.gov/publications/status-report-fourth-round-nist-post-quantum-cryptography-standardization-process>
43. Classic McEliece team, *ISO* (ISO/IEC 18033-2 amendment, 2026). <https://classic.mceliece.org/iso.html>
44. NIST, *NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption* (11 Mar 2025: a draft in about a year, the final standard in 2027). <https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption>

## In progress

- **ChirpStack as the network server** (branch `LoRa_1.1_implementation`): steps and status in
  [pending.md](pending.md). Built and tested on one Mac (findings 115-118): uplinks, `lorawan11_e2e`, downlinks,
  the delay, ChirpStack's TLS, and PQ TLS on every link through stunnel with the device on a UDP "air";
  as required, a separate PQ MQTT broker after ChirpStack (119).
  Waiting for the two-machine run (Pi gateway → Mac ChirpStack) and the Pico W's run.

## Future implementations (KIV)

- **LoRaWAN OTAA join through the broker (KIV).** The join (Join-Request / Join-Accept) was timed only locally, so it
  was removed (finding 76). Measuring it now means sending the join messages through the MQTT broker.
- **Pico 2 W (RP2350) runs**, pending the board.

## Hardening (tracked)

From the security review of 8 Oct (the constrained-device key-management guidance: seeds kept like private keys,
side-channel protection, hedged ML-DSA). Not implemented yet unless the status says so; *Done so far* lists
what is already in place, measured or tested in each area.

| Area | Our setup now | Risk | Solution | Done so far | Status |
|---|---|---|---|---|---|
| Device identity | One client key per certificate set, compiled into every firmware built with it (`mt_secrets.h`) | Every board shares the key; it travels in each image | On-device key generation + CSR to the CA, one identity per device (ML-DSA-44 keygen 25 ms on the Pico) | mTLS device certificates for all 18 certificate types, 50 connections each on the Pico W; the key and certificate are written per build into `mt_secrets.h` in the build folder, never committed; on-device ML-DSA-44 keygen measured (25 ms) | not started |
| Key / seed storage | Private key (PKCS#8) and the Wi-Fi password in flash, unencrypted; LoRaWAN keys, FCnt, trust anchor in LittleFS, plain | RP2040 flash is readable over USB BOOTSEL / SWD; no OTP, secure boot or flash encryption | Keep 32 / 64 B seeds (ML-DSA / ML-KEM) and re-derive at boot; seeds in RP2350 OTP or a secure element; LittleFS encrypted under an OTP-derived key | Wi-Fi password and keys only in the generated build header, committed files checked for `WIFI_PASS` / `WIFI_SSID` before pushes; FCnt reserved ahead in LittleFS, so a reboot never reuses a counter (finding 109) | not started |
| Boot and debug | RP2040: no secure boot, SWD always on | A changed image or a debugger reads / alters keys | RP2350 secure boot (signed images, boot key in OTP), debug locked via OTP; it raises the cost (the RP2350 hacking challenge was won by fault injection), a secure element for high-value keys | Options identified: RP2350 secure boot + OTP debug lock; ESP32 Secure Boot v2 + flash encryption (planned port, 9 Oct) | not started (pending Pico 2 W) |
| Randomness | `pico_rand` (128-bit software PRNG, ring oscillator + timer entropy) used directly as wolfSSL's RNG (`CUSTOM_RAND_GENERATE_BLOCK`); liboqs the same | ML-KEM / X25519 keys, TLS randoms and the ML-DSA hedge rest on it; no health tests | wolfSSL's Hash_DRBG (SP 800-90A) seeded from the hardware (`CUSTOM_RAND_GENERATE_SEED`, SP 800-90B seed tests); RP2350 TRNG; liboqs through the same DRBG | RNG path traced in the 8 Oct review; SNOVA's liboqs calls draw from wolfSSL's RNG (`wb_snova.c`), not a second source | not started |
| Constant-time code | wolfSSL ECC / RSA timing resistance on; BearSSL `br_aes_ct` for LoRaWAN AES; the Pico's MIC check uses `memcmp` (`lora_aead.h`), the host `CRYPTO_memcmp` | Timing of a MIC check leaks how many bytes matched (a forgery aid for frames from the air) | Constant-time compare on the Pico; check with a timing test (dudect-style) | `TFM_TIMING_RESISTANT`, `ECC_TIMING_RESISTANT`, `WC_RSA_BLINDING` set (`wolfssl_user_settings.h`); constant-time AES (`br_aes_ct`) for LoRaWAN; host MIC check constant-time; the Pico's `memcmp` located (`lora_aead.h`) | not started |
| Signing (side channels, faults) | ML-DSA hedged (wolfSSL draws 32 random bytes per signature); Falcon (float emulation) and SNOVA (memory-optimised) sign on the device in their runs | Falcon signing has published power / EM attacks; the SNOVA code is unprotected; a glitched lattice signature can leak the key | ML-DSA (hedged) for device signing, Falcon verify-only; verify-after-sign (+27 ms per ML-DSA-44 signature); masked code or a secure element where physical attacks matter | ML-DSA hedging confirmed in wolfSSL's code (8 Oct); the device's signing cost per mTLS handshake measured for every type (`hs_sign`: Falcon-512 1,001 ms, RSA-2048 973 ms, ML-DSA-44 139 ms) | hedging in place; rest not started |
| Power / EM side channels | No masking or shuffling in any device code (wolfSSL, liboqs, BearSSL); ephemeral key exchange keys (one per handshake) | The long-term signing key (mTLS, signed KEM exchange) can be targeted with many traces; SNOVA and Falcon signing most of all | Masked implementations or a secure element for the signing key; fewer signatures (resumption); Falcon verify-only | Fresh key-exchange keys in every handshake (X25519MLKEM768); the long-term keys on the device listed (mTLS key, signed KEM exchange key) | not started |
| Long-term key use | Full handshake on every connection (`NO_SESSION_CACHE`, no tickets) | Each connection signs with the device key: more exposure, and 3-12 s per SNOVA mTLS handshake | TLS 1.3 resumption with a fresh key exchange (`psk_dhe_ke`); protect the tickets | Signing cost per handshake measured for all 18 types, which sizes what resumption saves | not started |
| Trust anchor at rest | Signed update verified when it arrives (finding 109), then the certificate is kept | A flash edit could swap the root on a device that boots from it | Keep the signed bundle; re-check its ML-DSA-44 signature at each boot (33 ms) | The update is verified (ML-DSA-44, 33 ms) before it is stored; refused under the old root, then reconnected under the new one (Pico W 109, Pi 4 111) | not started |
| Revocation | Device: the broker's certificate against its CA's CRL, for every certificate type (deployment runs: host OpenSSL + wolfSSL, the Pico); broker: no CRL for device certificates | A revoked device certificate is still accepted by the broker | Mosquitto `crlfile` for ClientCA; short-lived device certificates (renewed through the CSR path) | A CRL per CA for all 9 types; revoked, expired and wrongly named broker certificates refused (Mac, Pico W, Pi 4: 54 / 54); CRL cost measured (Pico 8-98 ms per load; OpenSSL +0.19-1.28 ms per handshake) | device side done (findings 112-114: Mac, Pico W, Pi 4); broker side not started |
| Trust-anchor update format | `PQTA` \| CA length \| CA \| ML-DSA-44 signature: no version, no expiry | An old signed update can be replayed: a rollback to an earlier (perhaps compromised) root | A version and an expiry inside the signed bytes; keep the highest version seen in flash / OTP and refuse lower ones | Signed format with a length field; a changed byte in the length, the CA or the signature is refused (`deploy_host_test`) | not started |
| Update key | `certs/DEPLOY/update.key` made next to the CA, on the broker machine | Whoever holds it can install any root on every device | Keep it offline (HSM or an air-gapped machine), apart from the CA; a second key in firmware for recovery | A separate ML-DSA-44 update key, not the CA's; the device holds only its public half (`UPD_PUB`) | not started |
| ChirpStack backend (branch) | ChirpStack's Mosquitto: PQ listener 8883 for gateways (TLS 1.3, X25519MLKEM768 only, ML-DSA-44, client certificate required), plain only inside Docker and on 127.0.0.1:1884; ChirpStack's events to the project's PQ MQTT broker through stunnel (ML-DSA-44 mTLS). The UI (8080), its admin password and `[api] secret` are still the compose defaults; certificate keys are mode 644 for the containers; the broker's address isn't checked toward the MQTT broker (its certificate names only localhost) | Anyone on the LAN can reach the UI with the default login; the plain listener is open to local users of the Mac | New admin password and API secret; keys 600 per service; a certificate for the MQTT broker that names its address; a CRL for these CAs | PQ on both sides of ChirpStack, classical and certificate-less clients refused (findings 118, 119); `lorawan11_e2e` keeps the reading AES-256 encrypted past ChirpStack (116); ChirpStack's own TLS measured (117); the gateway's UDP on 127.0.0.1 | broker sides done (Mac + Pi broker); UI login, API secret, address check not started |

