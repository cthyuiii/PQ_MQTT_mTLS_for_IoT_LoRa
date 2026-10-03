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
    - **wolfSSL client with MAYO or SNOVA: not fixable.** wolfSSL has no implementation.
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
      - Not possible on the Pico: SLH-DSA (the broker can't serve it, finding 12) and MAYO / SNOVA (not in wolfSSL).
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

## In progress (planned, waiting for the go)

What a real deployment adds on top of the benchmark. Each one gets a plan here and is built only when approved.

- **Trust-anchor updates through signed firmware.** The Pico's CA certificate is compiled into its firmware, so
  moving devices to a post-quantum root means shipping the new CA securely.
  - Plan: keep the CA in a LittleFS file instead of the firmware. An update message on an MQTT topic carries the
    new CA plus an ML-DSA signature from an "update key" whose public half is baked into the firmware. The Pico
    verifies it (wolfSSL ML-DSA, already built in), writes the file and reconnects under the new CA.
  - A host script signs and publishes the update.
  - Measures: verify time, flash write time, bytes, and the first handshake under the new root.
  - arduino-pico's `PicoOTA` / `Updater` could carry a whole signed firmware image later.
- **Hostname checks, a CRL and NTP on the Pico.** Today the Pico checks only that the broker's chain ends at the
  CA: no name check, no revocation list, and no dates (`NO_ASN_TIME`).
  - Plan for the name check: `gen_certs.sh` adds the broker's IP / name to the server certificate's SAN (now
    `localhost`, `127.0.0.1`), and the sketch calls `wolfSSL_check_domain_name`.
  - Plan for revocation: `gen_certs.sh` also issues a CRL. wolfSSL gets `HAVE_CRL`, and the sketch loads the CRL
    with `wolfSSL_CTX_LoadCRLBuffer` and enables it.
  - Plan for time: the sketch sets the clock with arduino-pico's `NTP` before connecting, and wolfSSL drops
    `NO_ASN_TIME`. This needs an NTP server the Pico can reach (internet, or `chrony` on the Pi).
  - Measures: the added handshake time, flash and RAM, against today's runs.
  - The host clients get the same checks (OpenSSL `SSL_set1_host` and CRL flags; wolfSSL the same calls).
- **Keep FCnt across Pico reboots.** FCnt is part of every frame's nonce: restarting it under the same keys reuses
  nonces.
  - Today the keys are new on every boot, so nothing repeats.
  - Plan: store DevAddr, the keys and FCnt in a LittleFS file. Save FCnt every N frames, and on boot continue from
    the saved value plus N, so a counter never repeats even after a crash between saves.
  - Measures: the flash write per save and its effect on per-message time.
- **KEM exchange inside mTLS.** The KEM exchange now sends raw public keys and ciphertexts over the plain MQTT
  listener, so a man in the middle could swap a public key.
  - Plan, two variants: (a) the same exchange over the mTLS listener, the Pico and `mqtt_kem_timer` both
    presenting certificates; (b) over plain MQTT with each public key / ciphertext signed by ML-DSA.
  - Measures: added time and bytes against the plain exchange (finding 8).

## Future implementations (KIV)

- **ChirpStack as the network server.** It sits between gateway and application
  ([how_it_works.md section 3.1](how_it_works.md#31-what-each-one-is)). It would add two things:
  - an interop check that a real network server accepts our frames;
  - PQ TLS on its own MQTT links, which is untested.

  It needs a gateway, or a simulated one. None of the numbers above depends on it.
- **SLH-DSA in TLS.** A patched oqs-provider with the draft codepoints [36] (findings 12 and 51).
- **LoRaWAN OTAA join through the broker.** The join (Join-Request / Join-Accept) was timed only locally, so it
  was removed (finding 76). Measuring it now means sending the join messages through the MQTT broker.
- **Fix the Pico W Wi-Fi stall** (finding 75), after the 133 MHz check.
