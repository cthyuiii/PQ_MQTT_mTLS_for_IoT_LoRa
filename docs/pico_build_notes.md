# PQC Signatures on the Raspberry Pi Pico (RP2040) — Build & Bug Log

How each runnable signature scheme was brought up on the RP2040 (Raspberry Pi Pico /
Pico WH, Cortex‑M0+ @ 200 MHz, 264 KB SRAM, `arduino-pico` / Earle Philhower core), by
adapting existing reference / liboqs / PQClean code into self‑contained Arduino sketches —
and the bugs hit along the way.

All sketches are built for the **plain Pico** target (`rp2040:rp2040:rpipico`), benchmarked at
200 MHz, and seeded from the RP2040 hardware RNG (`rp2040.hwrand32()`).

> **2 Oct 2026:** the MAYO, SNOVA and MQOM2 sketches below (`mayo_bench`, `snova_zoo_bench`, `mqom_bench`) and the
> UOV pkc variants were replaced by NIST round 3 sets from liboqs main (`liboqs_bench`, `LIBOQS_ROUND=3`), as round 3
> changed their parameters. `sdith2_bench` (never compiled on 32-bit) is removed. `faest_em_128f_bench` and
> `qruov_cat1_bench` became `-D` variants of `faest_bench` and `qruov_zoo_bench`. The old sketches are in git history.

---

## 1. Shared methodology (applies to every sketch)

Every PQC sketch follows the same "port recipe" that turns an upstream C reference / liboqs /
PQClean tree into one Arduino sketch folder (`<algo>_bench/` with `<algo>_bench.ino` + `src/`).

**The port recipe**

1. **Flatten the source tree.** Upstream code lives in nested folders with a build system
   (Makefile/CMake/autoconf). Arduino compiles every `.c`/`.cpp` in `src/` flat, so all sources
   are copied into a single `src/` directory.
2. **Bake the build config into a header.** Reference builds select parameters via compiler
   defines (`-DPARAM=…`) or an autoconf `config.h`. Those are replaced by a single baked header
   (e.g. `mayo_config_pico.h`, `mqom2_config_pico.h`, `sdith_config_pico.h`,
   `faest_config_pico.h`) that every `.c` pulls in, so no build flags are needed.
3. **Fix includes for a flat tree.** Subdirectory includes (`#include "oqs/sha3.h"`) are
   rewritten to the flattened path (`../fips202.h`, `"common.h"`), and `<angle>` includes of
   bundled headers are changed to `"quote"` includes so Arduino finds them in `src/`.
4. **`.inc` → `_inc.h`.** Files included as templates with a `.inc` extension are renamed to
   `*_inc.h` (Arduino only compiles/handles known extensions).
5. **Match the `randombytes` ABI.** Each upstream expects a specific signature
   (`int randombytes(uint8_t*, size_t)`, `int randombytes(unsigned char*, unsigned long long)`,
   `void randombytes(uint8_t*, size_t)`, or `PQCLEAN_randombytes`). The sketch defines exactly
   that signature and fills it from `rp2040.hwrand32()`.
6. **Host‑verify first.** The sandbox has no `arm-none-eabi-gcc`, so each port is compiled with
   host `gcc`/`g++` plus a small harness that runs `keypair → sign → open` and checks the
   round‑trip. This catches include/ABI/C++ errors before flashing. (It does **not** catch
   target‑specific issues like stack size or unaligned access — those are validated on‑device.)

**Shared benchmark harness (`report_op`).** Every sketch reports, per operation
(keygen / sign / verify): mean, median and std in µs and ms; min/max; mean and median **cycles**
(`µs × 200`); and **ops/s**, plus the `pk / sk / sigMax / sig` sizes. Timing uses `micros()`.

**The "big‑stack" technique (`bigstack.h`).** `arduino-pico` caps the core‑0 stack at ~8 KB with
an overflow guard. Schemes whose working set exceeds that — but still fits in the 264 KB SRAM —
run each crypto call on a large stack *carved from SRAM* via a one‑time Cortex‑M0+ stack‑pointer
switch (a tiny `naked` function: save SP → `mov sp, bigbuffer_top` → call the op → restore SP).
The reference C is left **unmodified**; only the `.ino` changes. Used by MAYO‑1/2 (224 KB),
MQOM‑cat1 (100 KB), SDitH‑cat1 (48 KB).

**One‑shot runner (`run_benchmarks.py`).** Compiles each sketch, flashes it by byte‑copying
the `.uf2` onto the mounted `RPI-RP2` BOOTSEL volume, opens serial (which releases the sketch's
`while(!Serial)` wait), captures the report to a per‑algo log, and appends a parsed row to
`logs/results.csv`. Runs unattended.

---

## 2. Runnable schemes

### Lattice

**ML‑DSA‑44 / 65 / 87** (FIPS 204) — *runs natively, no special handling.*
- **Source / how added:** `mldsa-native` "ref" C (the implementation liboqs ships — same lineage
  as the Mac/Pi numbers) + PQClean `fips202.c` as the SHAKE backend via a small glue header.
  Parameter level is a baked config. Sizes: pk 1312/1952/2592, sig 2420/3309/4627.
- **Bugs / notes:** None blocking. ML‑DSA‑87 has the largest footprint and leans on the stack
  growing into the (empty) heap arena; it works for these runs. On‑device ML‑DSA‑44 ≈ keygen
  27.9 ms / sign ~115 ms (variable, rejection sampling) / verify 30.7 ms.

**Falcon‑512 / 1024** (FN‑DSA) — *runs, but slow keygen/sign (no FPU).*
- **Source / how added:** PQClean `crypto_sign/falcon-{512,1024}/clean` + `fips202.c`,
  unmodified, flattened into `src/`. Sizes: pk 897/1793, sig ≤ 752/1462.
- **Bugs / notes:** Falcon keygen and sign use floating‑point FFT Gaussian sampling; the M0+ has
  **no FPU**, so doubles run in software emulation → keygen/sign are slow. Verify is integer and
  fast. No code changes were needed — just the expectation that FP ops are soft‑float.

**HAWK‑512 / 1024** (NIST round‑2 onramp, lattice/NTRU) — *runs.*
- **Source / how added:** HAWK NIST `Reference_Implementation`, with its bundled SHA‑3 and
  fixed‑point NTRU keygen, flattened into `src/`. Self‑contained (no OpenSSL). Sizes: pk
  1024/2440, sig ≤ 555/1221.
- **Bugs / notes:** Straightforward port; host‑verified round‑trip OK. Both levels fit and run.

### Hash‑based

**SLH‑DSA / SPHINCS+ — 12 variants** (FIPS 205: SHA2 & SHAKE × 128/192/256 × f/s) — *run; 's' is very slow.*
- **Source / how added:** PQClean `crypto_sign/sphincs-{sha2,shake}-{128,192,256}{f,s}-simple/clean`
  + `fips202.c` / `sha2.c`. Hash‑based, so the M0+ runs them natively (no FP, no big RAM).
  Each variant is its own sketch (12 total). Sizes scale from pk 32 / sig 7856 (128s) up to
  sig 17088 (128f) and larger.
- **Bugs faced & fixed:**
  - **`'f'` variants — "stray `#`" compile error.** The generated `extern "C" { #include … }`
    placed the `#include` on the same line as the brace; split it onto its own line.
  - **`'s'` variants — `siglen` not in scope / doubled `sigMax=`.** The script that injected the
    size‑printing lines double‑applied a pattern (and `siglen` isn't defined for the fixed‑size
    SLH‑DSA API). Fixed by using the fixed `CRYPTO_BYTES` (`NS_SIG`) for both `sigMax` and `sig`.
  - **Note:** the `'s'` (small‑signature) variants are minutes‑per‑sign on the M0+; built and
    host‑verified, benchmarked at `ITERS=1` with per‑stage prints so progress is visible.

### Multivariate

**MAYO‑1 / MAYO‑2** (NIST round‑2 onramp) — *run via the big‑stack; MAYO‑3/5 are infeasible.*
- **Source / how added:** liboqs `mayo` "opt" (portable C) + PQClean AES + PQClean `fips202`,
  config‑driven by `MAYO_VARIANT`. `mayo.c` is **unmodified**. Sizes: MAYO‑1 pk 1420 / sig 454,
  MAYO‑2 pk 4912 / sig 186.
- **Bugs faced & fixed:**
  - **`crypto_sign` signature mismatch.** MAYO's API takes `size_t *smlen`, not
    `unsigned long long *`; the sketch's length variables were changed to `size_t`.
  - **"MEM_FAULT" false positive (the big one).** A host‑side watchdog/timeout guard was
    resetting MAYO mid‑run; it was misdiagnosed as an architectural failure. Root cause:
    MAYO's reference scatters 30–54 KB arrays across its call chain (measured peak ≈ 210 KB for
    verify), which **fits in 264 KB SRAM but blows the 8 KB stack guard**. **Fix:** run each op on
    a **224 KB SRAM big‑stack** (SP switch) — validated on‑device (verify peak 214,800 B, matching
    the host‑measured 215,040 B). On‑device MAYO‑1: keygen 428 ms / sign 837 ms / verify 317 ms.
  - **Why MAYO‑2 is faster than MAYO‑1** (worth noting in the report): same NIST level‑1, but
    runtime is set by `m` and `k` (whipped repetitions), not pk size. MAYO‑1 has k=10, MAYO‑2 k=4,
    so MAYO‑2 sign/verify are ~1.4–1.6× faster despite the larger public key.

**QR‑UOV cat1** (`qruov1q127L3v156m54`) — *runs (cat1 only).*
- **Source / how added:** NIST round‑2 QR‑UOV reference, flattened into `src/`. Sizes:
  pk 24256 / sig 200.
- **Bugs faced & fixed:**
  - **OpenSSL dependency.** The reference uses OpenSSL EVP for its AES/SHAKE PRG, which isn't
    available on‑chip. Replaced with an **EVP → PQClean SHAKE shim** (`src/evp_pqclean_shim.h`)
    over PQClean FIPS202, and forced `QRUOV_PRG_SHAKE` so the SHAKE path is used. Host‑verified
    round‑trip OK.
  - **Only cat1 fits.** pk = 24 KB fits; cat3/cat5 public keys (72 KB / 174 KB) and their
    expanded maps exceed the SRAM, so they were not built.

**UOV ov‑Ip classic** (`OV(256,112,44)`, NIST L1) — *sign + verify run (keys baked in flash); keygen is infeasible.*
- **Source / how added:** the `pqov/pqov` reference (CC0/Apache‑2.0), variant `_OV_CLASSIC`,
  `PROJ=ref` (pure reference BLAS, no SIMD), flattened into `src/`. Sizes: **pk 278 432 (272 KB),
  sk 237 896 (232 KB), sig 128**. Host‑verified keygen→sign→verify→tamper before embedding.
- **How it was made to fit:**
  - **No OpenSSL.** The repo's `config.h` auto‑selects an OpenSSL AES/SHAKE backend; commenting out
    that auto‑`#define _UTILS_OPENSSL_` drops it onto the **portable** path — the bundled PQClean
    `fips202` (SHAKE256) for hashing and the repo's **4‑round bitsliced AES** (`aes128_4r_ffs.c`)
    for the public‑matrix PRG. Fully self‑contained C.
  - **`randombytes` namespacing.** pqov renames `randombytes` → `pqov_uov_Ip_ref_randombytes` via
    `utils_randombytes.h`; the sketch includes that header so its `hwrand32`‑backed definition gets
    the same name (and matches pqov's **`void`** return type, not the usual `int`).
- **RAM reality (the key finding):** keygen materialises pk **and** sk simultaneously ≈ **504 KB of
  scratch**, which exceeds even the RP2350's 520 KB once stack/USB/working buffers are counted →
  **keygen infeasible on either board.** But `ov_sign`/`ov_verify` (classic) take the key by a
  `const` pointer and use only a few KB of stack, so a **deterministic keypair is precomputed on
  host and baked into flash** (`src/baked_keys.h`, ~504 KB of `const` arrays kept in XIP flash);
  sign/verify then read the key straight from flash and **run on both RP2040 and RP2350**.
- **What's dropped:** keygen (RAM wall). The `_OV_PKC_SKC` compressed‑key variant would make keygen
  fit (sk shrinks to a seed) but changes the scheme's stored sizes, so it was left as a future option.

### MPC‑in‑the‑head (the hardest ports)

**MQOM2 cat1‑gf256‑fast‑r3** (NIST round‑2 onramp) — *runs after a CPU‑specific fix; cat3/cat5 infeasible.*
- **Source / how added:** NIST `signatures/MQOM` reference (bundled Rijndael + XKCP Keccak),
  flattened into `src/`, with `mqom2_config_pico.h` baked in (memory‑efficient BLC path). Sizes:
  pk 80 / sk 128 / sig ≤ 4164. Runs on a **100 KB big‑stack** + ~112 KB malloc heap.
- **Bugs faced & fixed:**
  - **`common.h` not found.** Angle‑bracket project includes were rewritten to quote includes.
  - **"Stuck after keygen" — first misdiagnosis.** With a 32 KB big‑stack sign overflowed; with
    160 KB it starved the heap. Investigation revealed MQOM is **not** pure‑stack — it allocates
    through a `mqom_malloc` *macro* (so a literal `malloc(` grep missed it). Sign needs **both**
    ~16 KB stack (M0+‑inflated) **and** ~112 KB heap; the fix was a *balanced* split: 100 KB
    big‑stack leaving ~120 KB heap.
  - **The real blocker — Cortex‑M0+ unaligned access in Keccak (shared with SDitH).** Even
    balanced, sign HardFaulted. On‑device fault instrumentation (a HardFault handler that stores
    the faulting PC in watchdog scratch across a reset) + `addr2line` pinpointed two unaligned
    64‑bit accesses that the M0+ traps but x86 tolerates:
    1. **`sign.c` aliased a byte buffer as the Keccak context** (`xof_ctx = (xof_context*)x0`),
       so the opt64 permutation wrote the **state** as 64‑bit lanes at a 1‑byte‑aligned address.
       Fixed by using the (8‑byte‑aligned) stack XOF context — exactly what MQOM's own libOQS
       build already does.
    2. **The opt64 Keccak reads the *input data* as 64‑bit lanes** in `KeccakP1600_AddLanes`
       (which ships a byte‑wise fallback gated by `NO_MISALIGNED_ACCESSES`) and in the unguarded
       `KeccakF1600_FastLoop_Absorb`. Fixed by **defining `NO_MISALIGNED_ACCESSES`** and
       **disabling the FastLoop** (`KeccakF1600_FastLoop_supported`) so the sponge uses the
       memcpy‑based path. (keygen only ever absorbs tiny inputs, which is why it never faulted.)
  - **cat3 / cat5 are infeasible:** measured sign heap 372 KB / 878 KB > 264 KB SRAM. Would need
    the in‑place GGM‑tree rewrite the reference itself flags as a `TODO`.

**SDitH threshold cat1‑gf256** (NIST round‑2 onramp) — *runs after the same Keccak fix; cat3/cat5 infeasible.*
- **Source / how added:** NIST `signatures/SDitH` `Threshold_Variant` reference (bundled XKCP
  Keccak), flattened into `src/`, level set in the baked config. Sizes: pk 132 / sk 432 /
  sig ≤ 10684. Heap‑heavy: sign mallocs ~166 KB, so it runs on a **48 KB big‑stack** (covers its
  stack) leaving ~168 KB heap (tight but sufficient).
- **Bugs faced & fixed:**
  - **C++ `void*` → `uint8_t*` errors.** The reference is C; compiled as Arduino C++ it rejected
    implicit `void*` conversions in `field.h` — added explicit `(uint8_t*)` casts.
  - **Same Cortex‑M0+ unaligned‑Keccak HardFault as MQOM.** SDitH's fault landed directly in
    `KeccakF1600_FastLoop_Absorb` (same shared XKCP opt64). Fixed with **`NO_MISALIGNED_ACCESSES`
    + FastLoop disabled** (SDitH's Keccak state was already aligned, so it didn't need the
    context‑alias fix).
  - **cat3 / cat5 infeasible:** sign heap 337 KB / 575 KB > 264 KB SRAM.

### Classical baselines (reference points, not PQC ports)

**ECDSA‑P256 / P384 / P521** — *run, via the core's bundled BearSSL.*
- **Source / how added:** BearSSL (already bundled in `arduino-pico`), not a PQClean port.
  P‑256 uses the constant‑time `br_ec_p256_m15`; P‑384/P‑521 use the generic `br_ec_get_default`
  (the m15 impl is P‑256‑only). HMAC‑DRBG seeded from `hwrand32()`. Sizes: pk 64/96/132, sk
  32/48/66.
- **Bugs / notes:** Could not be host‑verified in the sandbox (no BearSSL there); validated
  on‑device. If the include path differs by core version, use `<bearssl.h>`.

**RSA‑2048 / 3072** (PKCS#1 v1.5 / SHA‑256) — *run, but keygen is very slow/variable.*
- **Source / how added:** BearSSL `br_rsa_keygen` / `br_rsa_pkcs1_sign` / `…_vrfy`. Sizes: pk
  256/384 (modulus). `ITERS` kept low with per‑stage prints.
- **Bugs / notes:** RSA keygen is a randomized prime search → tens of seconds to minutes on the
  M0+ and highly variable; the keygen call is a single long silent block, so the runner uses very
  long (or `--no-timeout`) idle windows for these. This M0+ slowness is itself a useful baseline
  result (a Pico 2 / RP2350 with hardware multiply + more registers is dramatically faster).

**Ed25519 / Ed448** (RFC 8032 EdDSA) — *run; the curve‑448 quantum‑resistance bar is 224‑bit.*
- **Ed25519:** the rweather **"Crypto"** Arduino library (`Ed25519::derivePublicKey/sign/verify`);
  install once with `arduino-cli lib install Crypto`. pk/sk 32, sig 64.
- **Ed448:** no Arduino library exists, so OpenSSL's self‑contained **Ed448‑Goldilocks**
  (`crypto/ec/curve448/`, Mike Hamburg origin, Apache‑2.0) was flattened into `src/`. pk/sk 57,
  sig 114.
  - **EVP → PQClean SHAKE.** The reference hashes through OpenSSL's `EVP_DigestFinalXOF`; a tiny
    `shake_shim.h` reimplements just that slice (new/fetch/init/update/finalXOF/free) over PQClean
    `fips202` incremental SHAKE256.
  - **OpenSSL‑isms stubbed.** `ossl_compat.h` provides `ossl_inline`, `__owur`, `OPENSSL_cleanse`,
    `OSSL_LIB_CTX`; `ecx_shim.h` replaces `<crypto/ecx.h>` (the X448/Ed448 prototypes); the bundled
    `internal/constant_time.h` is used as‑is. Forced to the **portable 32‑bit field path**
    (`f_impl32.c`, no `__int128`) so the host‑verified code is byte‑identical to what the M0+/M33
    runs.
  - **Verified:** matches the **RFC 8032 section 7.4 Ed448** test vector (public key, signature, verify),
    rejects a tampered signature, and the NIST `crypto_sign` wrapper round‑trips. Tiny working set
    (a few KB) → no big‑stack needed.

---

## 3. Cross‑cutting issues hit during bring‑up

- **WiFi (cyw43) eats the stack.** Building for the **Pico W** (`rpipicow`) brings up the WiFi
  driver at boot, which consumed ~7 KB of the 8 KB system stack (observed as `free_stack ≈ 808`).
  Switching the build to the **plain Pico** (`rpipico`) reclaims it — WiFi isn't needed for
  benchmarking and `hwrand32()` works either way.
- **On‑device fault diagnosis pattern.** Because the M0+ HardFaults on unaligned access and the
  RP2040 has all SRAM mapped (so a stack overflow *corrupts silently and hangs* rather than
  faulting), a HardFault handler was used that stashes the faulting PC/LR/SP in the **watchdog
  scratch registers** (which survive a reset) and reboots; the next boot prints them, and
  `arm-none-eabi-addr2line` resolves the PC to `file:line`. This is what cracked the MQOM/SDitH
  unaligned‑Keccak bug and cleanly distinguishes "fault" vs "silent stack overflow" vs "heap NULL".
- **Flashing mechanics (macOS).** Sketches are flashed by byte‑copying the `.uf2` onto the mounted
  `/Volumes/RPI-RP2` BOOTSEL drive (a plain write, *not* `shutil.copy`, which the FAT volume
  rejects with `EPERM`); a 1200‑baud "touch" drops a running sketch into BOOTSEL; the terminal/
  Python needs macOS **Full Disk Access** to write the volume.

---

## 4. What was dropped, and why (not runnable on RP2040)

These exceed the 264 KB SRAM no matter how stack/heap are arranged (so they were skipped, not
"failed"): **MAYO‑3 / MAYO‑5** (expanded key 380 KB / 833 KB), **SNOVA** all levels (24‑5‑4 sign
needs a 263 KB stack), **MQOM cat3 / cat5** (heap 372 KB / 878 KB), **SDitH cat3 / cat5** (heap
337 KB / 575 KB), **FAEST** all levels (sign heap ≈ 280 KB+; compute is fine — it's a pure RAM
wall), **UOV** (*keygen only* — pk+sk ≈ 504 KB scratch; sign/verify now run with the keypair baked
in flash, see section 2), **SQIsign** (needs a 32‑bit field port; the reference uses
`__uint128_t`), and **CROSS** (excluded by request). Several of the cat3 cases (~340–370 KB) would
fit a Pico 2 / RP2350's 520 KB SRAM if the study is extended to that chip.

---

## 5. RP2350 failure investigation (host‑measured working sets)

When the cat3/RP2350 candidates first hit hardware they **timed out or hard‑faulted**. Host
instrumentation (a `ucontext` painted‑stack high‑water probe + a `--wrap malloc/free/calloc/realloc`
heap‑peak counter, run on the flattened `src/` of each sketch) pinned down the *real* cause per
scheme — and it was usually a **config bug in the sketch, not a fundamental RAM wall**:

| Scheme | Stack peak | Heap peak | Working set | Fits 520 KB? | Real cause | Fix |
| --- | --- | --- | --- | --- | --- | --- |
| **MAYO‑3** | **504 KB** | ~1 KB | ~505 KB | **No** (no margin) | genuinely pure‑stack 504 KB; *and* it ran on the 8 KB default stack → instant fault | none — true wall |
| **MQOM‑cat3** | 11 KB | 372 KB | **383 KB** | **Yes** (+137 KB) | sketch comment wrongly said "pure‑stack, no heap"; the 160 KB big‑stack **+** 372 KB heap = 532 KB > 520 → OOM | shrink big‑stack 160 → **32 KB** |
| **SDitH‑cat3** | ~10 KB | 337 KB | **~370 KB** | **Yes** (+150 KB) | `bigstack.h` shipped but **never invoked** — crypto ran on the 8 KB default stack → overflow | wrap ops in **40 KB** `big_stack_run` |
| **FAEST‑128f** | 6.7 KB | 424 KB | **430 KB** | **Yes** (+90 KB) | stack fine; 424 KB heap is borderline — likely a heap‑arena/`Pico 2 W` WiFi‑RAM OOM or a runner timeout, not a wall | re‑test on plain `rpipico2`; instrument if it still fails |
| **FAEST‑192f / 256f** | ~7 KB | ~600 / ~900 KB (scales) | wall | **No** | heap scales past 520 KB with the security level | none — true wall |
| **SNOVA‑L3 / L5** | ~260 KB+ (scales) | small | L3 borderline / L5 wall | partial | huge sign stack; sketch on default/undersized stack | board‑conditional big‑stack (L3); L5 likely a wall |

**Takeaways:** (1) MAYO‑3 is a *confirmed* RAM wall (504 KB) — drop it. (2) MQOM‑cat3 and SDitH‑cat3
**fit the RP2350** and failed purely because of an oversized / un‑wired big‑stack; both sketches are
now fixed (RP2350‑only configs) and ready to re‑flash. (3) FAEST‑128f *should* fit (430 KB) — re‑test
before judging. (4) The host probe (`ucontext` paint + `--wrap` heap counter) is the reusable tool
for answering "does a corrected config fit?" without burning device cycles.

---

## 6. Whole‑zoo sweep: scalable parameter‑set coverage (the 500 KB gate)

To cover *every* feasible zoo parameter set without duplicating a 157‑file `src/` tree per variant,
the config headers were made `#ifndef`‑overridable and the **runner now passes per‑variant `-D`
flags** to `arduino-cli` (`S(..., flags="-D...")` → `--build-property compiler.{c,cpp}.extra_flags`,
with a per‑label `--build-path` so variants never reuse each other's cached objects). One shared
`mqom_bench/` sketch therefore stamps **all feasible MQOM2 sets**.

**MQOM2 feasibility (host‑measured worst‑case working set, the gate = fits 520 KB):**

| field | L1 (sec128) | L3 (sec192) | L5 (sec256) |
| --- | --- | --- | --- |
| **gf256** | 119 KB ✅ both boards | 384 KB ✅ RP2350 only | 878 KB ❌ wall |
| **gf16**  | 97 KB ✅ both boards | 309 KB ✅ RP2350 only | 787 KB ❌ wall |
| **gf2**   | **522 KB ❌ wall** | 1759 KB ❌ | ❌ |

The surprise: **gf2 is the *heaviest* field, not the lightest** — GF(2) MQOM needs far more parallel
MPC repetitions, so its working set blows past 520 KB at *every* level (small signatures, huge RAM).
So the feasible MQOM set is **gf16 + gf256 × {L1,L3} × {fast,short} × {3r,5r} = 16 variants** (L1 on
both boards, L3 RP2350‑only); the 44 other MQOM zoo rows (all gf2, all L5) are confirmed walls. Each
of the 16 is host‑verified (`crypto_sign` round‑trip `open=0`) and under the 500 KB gate.

**SNOVA (`snova_zoo_bench`, PQCLAB‑SNOVA reference).** Same one‑src + `-D` pattern
(`SNOVA_v/o/q/l/r`, `SNOVA_OPT=ref`). The reference is SHAKE‑based (keccak_opt64) — no AES — so the
only OpenSSL dependency was the KAT‑DRBG `rng.c`, replaced by a 3‑line `randombytes` (hwrand32) + a
stub `rng.h`. SNOVA is **pure‑stack**; host‑measured sign peaks (RP2350‑only, run on a 456 KB
big‑stack): **24‑5‑16‑4 = 338 KB, 28‑4‑16‑4×5 = 396 KB, 28‑4‑19‑4×5 = 407 KB, 28‑5‑19‑4 = 425 KB** —
all under 500 KB. Host‑verified keygen/sign/open/tamper on 24‑5‑16‑4 (pk 1016, sig 248 — matches the
zoo). The old liboqs‑based `snova2454/2455/2965` sketches are superseded (folders can be deleted).

**SLH‑DSA** needed no work — all 12 (`sha2`+`shake`, 128/192/256, `f`+`s`) were already built and in
the runner.

**QR‑UOV** other variants are *not* a clean `-D` swap: the reference bakes hardcoded sizes into each
`api.h` and the raw sources include `openssl/sha.h`, so cat3/cat5 (q127, present locally under
`signatures/.../variants/`) each need the same flatten + EVP→PQClean SHAKE‑shim port that cat1
got, and the zoo's q31/q7 L1 sets need the `qruov/round2` clone.

**SDitH2‑gf2 (the zoo's SDitH) — ported** from the sdith.org package v2 (`sdith_cat1_fast`, flattened
into `sdith2_bench/`). VOLE‑in‑the‑head v2, self‑contained (bundled AES + XKCP Keccak, opt64 +
`NO_MISALIGNED_ACCESSES`), mixed C/C++. Host‑verified keygen/sign/open (pk 70, sk 163, sig 4484 —
matches the zoo). RAM reality: **keygen heap ~620 KB** (the SD parity‑check matrix) is a wall even on
520 KB, but **sign 246 KB / verify 252 KB** fit the RP2350 — so, like UOV, a deterministic keypair is
**baked into flash** and sign/verify run from it on a 32 KB big‑stack (RP2350‑only). All six v2 sets
share one src tree (param via `SIGNATURE_PARAMS`). *(The earlier `sdith/sdith` clone was the wrong
package — gf256/p251 only.)*

**Feasible‑straggler sweep (final pass).** Chased every remaining sub‑500 KB candidate; six were real
and are now imported, the rest measured out as walls:

- **QR‑UOV q31/q7 L1 (3 sets, done).** The field constants (`fc/fe/fc0`) were *not* from `find_tau`
  (which only emits `tau`) — they're tabulated in the clone's `src/qruov_config.src`
  (q31‑L3 = 1/1/1, q31‑L10 = 5/3/1, q7‑L10 = 2/1/1). One shared `qruov_zoo_bench` (config + sizes
  `#ifndef`‑guarded, sizes from `api_h_gen`) stamps them via `-D`. Host‑verified roundtrips
  (pk 23641/12266/20641, matching the zoo). Stack‑heavy (33–143 KB; M0+ inflates), so a
  board‑conditional big‑stack (208/256 KB) → both boards.
- **SDitH2‑L1‑gf2‑short (done).** Same shared `sdith2_bench` via `-D` (sig 3705, `CAT1_SHORT_PARAMETERS`);
  baked keypair; sign 246 / verify 323 KB → fits RP2350.
- **UOV Ip‑pkc + Is‑pkc (done).** pqov params are `-D`‑overridable; the compressed pk shrinks the key
  buffers, so with baked keys the only SRAM cost is verify *expanding* the pk (Ip ~272 KB, Is ~402 KB)
  → both fit RP2350 on a 32 KB big‑stack. Host‑verified.
- **SNOVA‑L3 — all walls.** Even the smallest (38‑5‑19‑4×5, pk 800) is 958 KB stack; 40‑7‑19‑4 is
  1.14 MB. The L1 sets were the feasible ceiling.
- **FAEST‑128s / EM‑128s — walls.** The 's' variants store the full VOLE tree, so they're the
  *heaviest*, not lightest: **128s sign heap ≈ 2.99 MB** (vs 128f's 424 KB). Same counterintuitive
  flip as MQOM‑gf2.

Net: QR‑UOV jumps 1→4 L1 sets, SDitH2 1→2, UOV 1→3. SQIsign is the only feasible‑on‑paper scheme
still unported (needs the `__uint128_t`→32‑bit field rewrite).
