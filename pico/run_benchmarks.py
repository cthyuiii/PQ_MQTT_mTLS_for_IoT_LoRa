#!/usr/bin/env python3
"""
run_benchmarks.py - board-aware, one-shot Pico PQC benchmark runner.

It DETECTS the connected board (RP2040 Pico / Pico W  vs  RP2350 Pico 2 / Pico 2 W),
picks the matching FQBN + BOOTSEL drive automatically, and then flashes ONLY the
algorithms that fit that board's SRAM - the ones too big for the chip are never
compiled or flashed. For each runnable sketch it: compile -> upload (UF2 copy) ->
open serial (releases the sketch's `while(!Serial)` wait) -> capture the report until
"=== done" (or an idle timeout) -> log it + append a parsed row to results.csv.

WHY a capability matrix: several schemes only fit the bigger RP2350 (520 KB) and
overflow the RP2040 (264 KB). Each sketch below is tagged with the board families it
can run on, so the runner gates them automatically per detected board.

----------------------------------------------------------------------------
PREREQUISITES (one-time; macOS, Linux, or Windows with Git for Windows' bash for the library builders):
  1. arduino-cli + the Earle Philhower RP2040/RP2350 core (rp2040:rp2040), pyserial.
  2. Put the board in BOOTSEL once if it's brand new; afterwards the core auto-resets.

USAGE:
  python3 run_benchmarks.py                      # auto-detect board, run all that fit
  python3 run_benchmarks.py --board rp2350       # skip detection, force a family
  python3 run_benchmarks.py --candidates         # also try RP2350 "size-feasible" extras
  python3 run_benchmarks.py --only mldsa_bench,falcon_bench          # every ML-DSA / Falcon set; --match ml-dsa-44 for one
  python3 run_benchmarks.py --skip rsa_bench           # every RSA size (--match rsa-2048 for one)
  python3 run_benchmarks.py --no-timeout         # wait forever (RSA keygen)
  WIFI_SSID=... WIFI_PASS=... BROKER=<ip> python3 run_benchmarks.py --test mqtt   # Pico W / Pico 2 W:
      MQTT over plain / TLS / mTLS + pipeline against ./run_all.sh --serve-broker on another machine
----------------------------------------------------------------------------
"""
import argparse, base64, csv, glob, json, os, re, shutil, statistics, subprocess, sys, tempfile, time

HERE   = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(HERE, "logs")
RUN_TAG = ""  # --tag: results/*_pico_<board>_<tag>.*, logs in logs_<tag>/ (another broker, ...)
ROOT   = os.path.dirname(HERE)
SKETCH_DIR = os.path.join(HERE, "sketches")  # one Arduino sketch per folder (folder name = .ino name)
# wolfssl_bench compiles against a generated wolfSSL Arduino library kept outside the repo
# the library builders are bash scripts: on Windows, Git for Windows' bash (System32\\bash.exe would be WSL's)
_GIT_BASH = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Git", "bin", "bash.exe")
BASH = _GIT_BASH if os.name == "nt" and os.path.exists(_GIT_BASH) else "bash"
WOLF_LIBS = os.path.join(os.environ.get("IOT_PQC_CACHE", os.path.expanduser("~/.cache/iot-pqc")), "arduino-libs")

# ---------------------------------------------------------------------------
# Board profiles. The non-W FQBN is used on purpose for BOTH the plain and the W
# variants: the crypto benches need no WiFi, and the non-W build frees the cyw43
# stack/RAM. hwrand32() works on every variant. (You can override with --fqbn.)
# mqtt_tls_bench is the exception: it builds for the W board (rpipicow / rpipico2w).
# ---------------------------------------------------------------------------
BOARDS = {
    "rp2040": dict(
        name   = "RP2040  (Pico / Pico W, Cortex-M0+, 264 KB SRAM)",
        fqbn   = "rp2040:rp2040:rpipico",
        label  = "RPI-RP2",                   # BOOTSEL drive label (INFO_UF2.TXT Board-ID)
        sram_kb= 264,
    ),
    "rp2350": dict(
        name   = "RP2350  (Pico 2 / Pico 2 W, Cortex-M33, 520 KB SRAM)",
        fqbn   = "rp2040:rp2040:rpipico2",
        label  = "RP2350",                    # Pico 2 mounts as RP2350, NOT RPI-RP2
        sram_kb= 520,
    ),
}

# ---------------------------------------------------------------------------
# Capability matrix.
#   boards : set of board families this sketch is known/expected to run on.
#   tier   : "ok"        = validated on that family (run by default).
#            "candidate" = fits the SRAM by size but NOT yet hardware-validated /
#                          may need its big-stack re-tuned; only runs with --candidates.
#   ws_kb  : measured peak working set (stack + heap) - the reason for the gating.
# Missing folders are skipped automatically, so unbuilt entries are harmless.
# ---------------------------------------------------------------------------
BOTH = ("rp2040", "rp2350")

def S(folder, label, timeout, boards, ws_kb, tier="ok", note="", flags="", lib=""):
    # flags: extra -D compile defines (e.g. parameter-set selection) passed to arduino-cli.
    # Lets one shared src tree (e.g. slhdsa_bench) stamp many parameter sets without duplicating files.
    return dict(folder=folder, label=label, timeout=timeout,
                boards=set(boards), ws_kb=ws_kb, tier=tier, note=note, flags=flags, lib=lib)

# Which implementation each sketch measures: results.csv "Library" column and the --lib filter.
LIB_BY_PREFIX = [("wolfssl_bench", "wolfssl"), ("mqtt_tls_bench", "wolfssl+bearssl+ascon-c"), ("liboqs_bench", "liboqs"),
                 ("ecdsa_", "bearssl"), ("rsa", "bearssl"), ("ed25519", "rweather-crypto"),
                 ("ed448", "openssl-goldilocks"), ("mldsa", "mldsa-native"), ("falcon", "pqclean"),
                 ("slhdsa", "pqclean"), ("", "reference")]
# liboqs main at run_all.sh's R3_LIBOQS (the round3 stage's): the NIST round 3 MAYO / SNOVA / MQOM / UOV parameter sets
R3 = "liboqs-r3"
def lib_of(s):
    return s.get("lib") or next(lib for prefix, lib in LIB_BY_PREFIX if s["folder"].startswith(prefix))
def libraries(s):
    """the Arduino libraries dir of a build: arduino-libs (wolfSSL, liboqs 0.16), -xkcp / -r3 (liboqs only), or for
    wolfSSL + round 3 liboqs (the SNOVA TLS firmware) -wolfssl-r3: links to both, as each dir has one liboqs"""
    if s["folder"] == "mqtt_tls_bench" and s["lib"] == R3:
        d = WOLF_LIBS + "-wolfssl-r3"
        os.makedirs(d, exist_ok=True)
        for name, src in (("wolfssl", WOLF_LIBS), ("liboqs", WOLF_LIBS + "-r3")):
            if not os.path.islink(os.path.join(d, name)):
                os.symlink(os.path.join(src, name), os.path.join(d, name))
        return d
    return WOLF_LIBS + {"liboqs+xkcp": "-xkcp", R3: "-r3"}.get(s["lib"], "")
def test_of(s):
    return "mqtt" if s["folder"] == "mqtt_tls_bench" else "pqc"
def norm(t):
    return re.sub(r"[^a-z0-9]", "", t.lower())

SKETCHES = [
    # LoRaWAN / AES / Ascon are measured only through the MQTT broker: mqtt_tls_bench's pipeline (below).
    # --- wolfSSL 5.9.4 = embedded-library alternative to the PQClean / mldsa-native / reference / BearSSL
    #     ports below (same wolfSSL release as the Pi). One algorithm per firmware (-DWB_*), small-mem
    #     ML-DSA/SLH-DSA, Cortex-M asm for ECDSA/RSA; the log's "peak heap" line is the RAM working set.
    #     Compile-checked for both boards; not yet run on hardware (ws_kb unknown until the first run).
    S("wolfssl_bench", "ML-DSA-44 (wolfSSL)",           120, BOTH, 0, flags="-DWB_MLDSA44"),
    S("wolfssl_bench", "ML-DSA-65 (wolfSSL)",           150, BOTH, 0, flags="-DWB_MLDSA65"),
    S("wolfssl_bench", "ML-DSA-87 (wolfSSL)",           180, BOTH, 0, flags="-DWB_MLDSA87"),
    S("wolfssl_bench", "SLH-DSA-SHA2-128f (wolfSSL)",   600, BOTH, 0, flags="-DWB_SLHDSA_SHA2_128F -DWB_ITERS=5"),
    S("wolfssl_bench", "SLH-DSA-SHA2-128s (wolfSSL)",  3600, BOTH, 0, flags="-DWB_SLHDSA_SHA2_128S -DWB_ITERS=3"),
    S("wolfssl_bench", "SLH-DSA-SHAKE-128f (wolfSSL)",  600, BOTH, 0, flags="-DWB_SLHDSA_SHAKE_128F -DWB_ITERS=5"),
    S("wolfssl_bench", "ECDSA-P256 (wolfSSL)",          120, BOTH, 0, flags="-DWB_ECDSA_P256"),
    S("wolfssl_bench", "Ed25519 (wolfSSL)",             120, BOTH, 0, flags="-DWB_ED25519"),
    S("wolfssl_bench", "RSA-2048 (wolfSSL)",           1800, BOTH, 0, flags="-DWB_RSA2048 -DWB_ITERS=5"),
    # wolfSSL's own Falcon (5.9.4, experimental; floating point emulated in integers on the M0+): the TLS client's code
    S("wolfssl_bench", "Falcon-512 (wolfSSL)",          900, BOTH, 0, flags="-DWB_FALCON512 -DWB_ITERS=5"),
    S("wolfssl_bench", "Falcon-1024 (wolfSSL)",        1800, BOTH, 0, flags="-DWB_FALCON1024 -DWB_ITERS=5"),
    # --- Stage 2 + pipeline on the Pico W / Pico 2 W (Wi-Fi FQBN): MQTT over plain / TLS 1.3 / mTLS, wolfSSL,
    #     X25519MLKEM768 (+ the key-exchange sweep), one certificate type per firmware (every one the broker serves
    #     and wolfSSL has: not SLH-DSA or MAYO; SNOVA below), against ./run_all.sh --serve-broker on another machine.
    #     Needs WIFI_SSID, WIFI_PASS, BROKER in the environment. Rows: results/*_pico_<board>.csv in the host's columns.
    S("mqtt_tls_bench", "MQTT/TLS RSA-2048 (wolfSSL)",   300, BOTH, 0, flags="-DWB_TLS -DWB_RSA2048 -DMT_SIG=RSA2048"),
    S("mqtt_tls_bench", "MQTT/TLS RSA-3072 (wolfSSL)",   300, BOTH, 0, flags="-DWB_TLS -DWB_RSA3072 -DMT_SIG=RSA3072"),
    S("mqtt_tls_bench", "MQTT/TLS ECDSA-P256 (wolfSSL)", 300, BOTH, 0, flags="-DWB_TLS -DWB_ECDSA_P256 -DMT_SIG=ECDSAP256"),
    S("mqtt_tls_bench", "MQTT/TLS Ed25519 (wolfSSL)",    300, BOTH, 0, flags="-DWB_TLS -DWB_ED25519 -DMT_SIG=ED25519"),
    S("mqtt_tls_bench", "MQTT/TLS ML-DSA-44 (wolfSSL)",  300, BOTH, 0, flags="-DWB_TLS -DWB_MLDSA44 -DMT_SIG=MLDSA44"),
    S("mqtt_tls_bench", "MQTT/TLS ML-DSA-65 (wolfSSL)",  300, BOTH, 0, flags="-DWB_TLS -DWB_MLDSA65 -DMT_SIG=MLDSA65"),
    S("mqtt_tls_bench", "MQTT/TLS ML-DSA-87 (wolfSSL)",  300, BOTH, 0, flags="-DWB_TLS -DWB_MLDSA87 -DMT_SIG=MLDSA87"),
    S("mqtt_tls_bench", "MQTT/TLS Falcon-512 (wolfSSL)", 300, BOTH, 0, flags="-DWB_TLS -DWB_FALCON512 -DMT_SIG=FALCON512"),
    S("mqtt_tls_bench", "MQTT/TLS Falcon-1024 (wolfSSL)", 300, BOTH, 0, flags="-DWB_TLS -DWB_FALCON1024 -DMT_SIG=FALCON1024"),
    # round 3 SNOVA certificates (certs/round3, the round 3 broker from :20830): wolfSSL has no SNOVA, so
    # make_wolfssl_lib.sh puts it in Falcon-512's place (wolfssl_bench/wb_snova.c, liboqs main's SNOVA: lib=R3, the
    # same code as the SNOVA rows above). The run is on a stack for SNOVA's signing: 39 / 35 / 26 KB (level I K / B / S),
    # 59 / 51 / 49 KB (III), 92 / 79 / 76 KB (V) in QEMU (M0+), as the board's own peaks; + 8 KB for wolfSSL.
    # No sweep (-DMT_NO_SWEEP): a level V mTLS handshake is ~7 s of SNOVA, and the groups were swept with the others.
    *[S("mqtt_tls_bench", f"MQTT/TLS SNOVA_{p} round 3 (wolfSSL+liboqs)", 600, BOTH, 0, lib=R3,
        flags=f"-DWB_TLS -DWB_SNOVA{c} -DMT_SIG=SNOVA{c} -DMT_NO_SWEEP -DMT_STACK_KB={kb}")
      for c, p, kb in (("1K", "I_K", 48), ("1B", "I_B", 44), ("1S", "I_S", 36), ("3K", "III_K", 68), ("3B", "III_B", 60),
                       ("3S", "III_S", 60), ("5K", "V_K", 104), ("5B", "V_B", 90), ("5S", "V_S", 88))],
    # the KEM exchange as MQTT messages through the broker's plain listener (the host's --kex; no certificate is used):
    # ML-KEM-512/768/1024, X25519, X25519MLKEM768 with wolfCrypt -> results/kem_exchange_*_pico_<board>. The second
    # builds wolfSSL's small Curve25519 code (CURVE25519_SMALL, the TLS firmware's until 1 Oct): the X25519 A/B.
    S("mqtt_tls_bench", "MQTT KEM exchange (wolfSSL)", 300, BOTH, 0,
      flags="-DWB_TLS -DWB_MLDSA44 -DMT_SIG=MLDSA44 -DMT_KEX_ONLY"),
    S("mqtt_tls_bench", "MQTT KEM exchange, small X25519 (wolfSSL)", 300, BOTH, 0,
      flags="-DWB_TLS -DWB_MLDSA44 -DMT_SIG=MLDSA44 -DMT_KEX_ONLY -DWB_SMALL_25519"),
    # deployment checks on certs/DEPLOY (gen_certs.sh --deploy <broker IP>): NTP dates, the CRL, the broker's IP, a signed
    # trust-anchor update, the KEM exchange over mTLS and signed, FCnt across a reboot (built with a LittleFS partition)
    S("mqtt_tls_bench", "MQTT deployment checks (wolfSSL)", 600, BOTH, 0,
      flags="-DWB_TLS -DWB_MLDSA44 -DWB_CHECKS -DMT_DEPLOY -DMT_SIG=DEPLOY"),
    # the same checks (connect plain / -checked, CRL, name, dates, the refused certificates; the CRL's load time) for the
    # other certificate types, each under its own CA and CRL (DEPLOY_SIGS=all gen_certs.sh --deploy <broker IP>)
    *[S("mqtt_tls_bench", f"MQTT deployment checks {name} (wolfSSL)", 600, BOTH, 0,
        flags=f"-DWB_TLS -DWB_{wb} -DWB_CHECKS -DMT_DEPLOY -DMT_DEPLOY_CHECKS -DMT_SIG=DEPLOY_{sig}")
      for name, wb, sig in (("RSA-2048", "RSA2048", "RSA2048"), ("RSA-3072", "RSA3072", "RSA3072"),
                            ("ECDSA-P256", "ECDSA_P256", "ECDSAP256"), ("Ed25519", "ED25519", "ED25519"),
                            ("ML-DSA-65", "MLDSA65", "MLDSA65"), ("ML-DSA-87", "MLDSA87", "MLDSA87"),
                            ("Falcon-512", "FALCON512", "FALCON512"), ("Falcon-1024", "FALCON1024", "FALCON1024"))],
    # --- liboqs 0.16 bare-metal (portable C): the same code the Pi/Mac run via oqs-provider and the host liboqs stage.
    #     One algorithm per firmware (-DLB_ALG=<liboqs id>); reports peak stack per op (painted big stack,
    #     -DLB_STACK_KB, default 160 KB RP2040 / 400 KB RP2350).
    S("liboqs_bench", "ML-DSA-44 (liboqs)",            120, BOTH, 0, flags="-DLB_ALG=ml_dsa_44"),
    S("liboqs_bench", "ML-DSA-65 (liboqs)",            150, BOTH, 0, flags="-DLB_ALG=ml_dsa_65"),
    S("liboqs_bench", "ML-DSA-87 (liboqs)",            180, BOTH, 0, flags="-DLB_ALG=ml_dsa_87"),
    S("liboqs_bench", "Falcon-512 (liboqs)",           300, BOTH, 0, flags="-DLB_ALG=falcon_512"),
    S("liboqs_bench", "Falcon-1024 (liboqs)",          600, BOTH, 0, flags="-DLB_ALG=falcon_1024"),
    S("liboqs_bench", "SLH-DSA-SHA2-128f (liboqs)",    900, BOTH, 0, flags="-DLB_ALG=slh_dsa_pure_sha2_128f -DLB_ITERS=3"),
    S("liboqs_bench", "SLH-DSA-SHA2-128s (liboqs)",   3600, BOTH, 0, flags="-DLB_ALG=slh_dsa_pure_sha2_128s -DLB_ITERS=2"),
    S("liboqs_bench", "SLH-DSA-SHAKE-128f (liboqs)",   900, BOTH, 0, flags="-DLB_ALG=slh_dsa_pure_shake_128f -DLB_ITERS=3"),
    S("liboqs_bench", "SLH-DSA-SHAKE-128s (liboqs)",  3600, BOTH, 0, flags="-DLB_ALG=slh_dsa_pure_shake_128s -DLB_ITERS=2"),
    # --- NIST round 3 MAYO / SNOVA / MQOM / UOV: liboqs main (lib=R3), memory-optimised builds. Round 3 changed
    #     MAYO-1/2 and UOV-Ip, gave SNOVA new sets (v, o, q, l, r, m1) and MQOM v3. Same code as the round3 stage.
    #     MAYO stack, this library's M0+ code in QEMU: MAYO-1 keygen / sign / verify 158 / 236 / 225 KB, MAYO-2
    #     125 / 153 / 363 KB. 224 KB overflowed in MAYO-1's sign; 240 KB is about the most the RP2040 has to give.
    S("liboqs_bench", "MAYO-1 round 3 (liboqs)",       300, BOTH, 237, lib=R3, flags="-DLB_ALG=mayo_1 -DLB_STACK_KB=240"),
    S("liboqs_bench", "MAYO-2 round 3 (liboqs)",       300, ("rp2350",), 363, lib=R3, flags="-DLB_ALG=mayo_2",
      note="verify needs 363 KB of stack: more than the RP2040's 264 KB of RAM"),
    S("liboqs_bench", "MAYO-3 round 3 (liboqs)",       600, (), 504, tier="infeasible", lib=R3, flags="-DLB_ALG=mayo_3",
      note="verify needs 504 KB stack (MAYO-3 is unchanged in round 3)."),
    *[S("liboqs_bench", f"SNOVA_{p} round 3 (liboqs)", 1200, BOTH, 0, lib=R3, flags=f"-DLB_ALG=snova_SNOVA_{p}")
      for p in ("I_K", "I_B", "I_S", "III_K", "III_B", "III_S", "V_K", "V_B", "V_S")],  # memopt: < 120 KB even at level V
    *[S("liboqs_bench", f"MQOM3-{p} round 3 (liboqs)", 2400, BOTH, 0, lib=R3, flags=f"-DLB_ALG=mqom_mqom3_{p}")
      for p in ("cat1_gf16_fast_ct", "cat1_gf16_short_ct", "cat1_gf2_shorter_ct")],
    # UOV secret keys are 238-349 KB: RAM for them only on RP2350, and only with a small big-stack
    S("liboqs_bench", "UOV-Is-pkc round 3 (liboqs)",  1800, ("rp2350",), 0, lib=R3, flags="-DLB_ALG=uov_ov_Is_pkc -DLB_STACK_KB=48"),
    S("liboqs_bench", "UOV-Ip-pkc round 3 (liboqs)",  1800, ("rp2350",), 0, lib=R3, flags="-DLB_ALG=uov_ov_Ip_pkc -DLB_STACK_KB=48"),
    # --- classical baselines (BearSSL) - small, run on every board ---
    S("ecdsa_bench", "ECDSA-P256 (BearSSL)",  90,  BOTH,   8, flags="-DPICO_VARIANT_p256"),
    S("ecdsa_bench", "ECDSA-P384 (BearSSL)",  90,  BOTH,   8, flags="-DPICO_VARIANT_p384"),
    S("ecdsa_bench", "ECDSA-P521 (BearSSL)", 120,  BOTH,   8, flags="-DPICO_VARIANT_p521"),
    # Ed25519 needs the rweather "Crypto" library installed (arduino-cli lib install Crypto);
    # it COMPILE_FAILs until then. Ed448 uses a self-contained OpenSSL Goldilocks port in src/.
    S("ed25519_bench",    "Ed25519",                90,  BOTH,  10),
    S("ed448_bench",      "Ed448 (RFC 8032)",       90,  BOTH,  10),
    S("rsa_bench", "RSA-2048/SHA-256", 1200, BOTH, 12, flags="-DPICO_VARIANT_2048"),  # keygen is a long silent block
    S("rsa_bench", "RSA-3072/SHA-384", 1800, BOTH, 16, flags="-DPICO_VARIANT_3072"),  # consider --no-timeout
    S("rsa_bench", "RSA-4096/SHA-512", 3600, BOTH, 24, flags="-DPICO_VARIANT_4096"),  # keygen MANY minutes; use --no-timeout
    # --- ML-DSA / Falcon (lattice) ---
    S("mldsa_bench",    "ML-DSA-44",             90,  BOTH,  50, flags="-DPICO_VARIANT_44"),
    S("mldsa_bench",    "ML-DSA-65",             90,  BOTH,  70, flags="-DPICO_VARIANT_65"),
    S("mldsa_bench",    "ML-DSA-87",            120,  BOTH, 100, flags="-DPICO_VARIANT_87"),
    S("falcon_bench",  "Falcon-512",           150,  BOTH,  40, flags="-DPICO_VARIANT_512"),  # soft-float on M0+, FPU on M33
    S("falcon_bench", "Falcon-1024",          240,  BOTH,  80, flags="-DPICO_VARIANT_1024"),
    # --- HAWK (lattice/NTRU): withdrawn by its team from the NIST process (round 3, 2026) ---
    S("hawk_bench",    "HAWK-512",             120,  BOTH,  40, flags="-DPICO_VARIANT_512"),
    S("hawk_bench",   "HAWK-1024",            150,  BOTH,  60, flags="-DPICO_VARIANT_1024"),
    # --- QR-UOV round 3 (spec v3.0): the package's reference code, SHAKE PRG; -DQRUOV_PARAM_<set> picks the set and the
    #     big stack is the host-measured peak + margin. All five level 1 sets fit the RP2040 now (round 2: cat1 only).
    *[S("qruov_bench", f"QR-UOV-{p} round 3", t, BOTH, kb, flags=f"-DQRUOV_PARAM_{p} -DPRG_IS_AES=0 -DBIG_STACK_BYTES={kb * 1024}u")
      for p, t, kb in (("1q127L3", 120, 48), ("1q31L3", 120, 48), ("1q127L10", 180, 88), ("1q31L10", 240, 104),
                       ("1q7L10", 300, 160))],
    # UOV-Ip round 3 classic (liboqs main, lib=R3): keygen needs ~600 KB, so uov_bench/make_uov_keys.sh makes the pair on
    # the host and it is baked into flash; sign / verify read it there (XIP) with 12 / 5.3 KB of stack: both boards.
    S("uov_bench",        "UOV-Ip round 3 (sign/vrfy)", 300, BOTH, 12, lib=R3,
      note="keygen on the host (both keys need ~600 KB of RAM); sign + verify only"),
    # --- SLH-DSA 'f' (fast) ---
    S("slhdsa_bench",  "SLH-DSA-SHA2-128f",  240, BOTH, 20, flags="-DPICO_VARIANT_sha2_128f"),
    S("slhdsa_bench", "SLH-DSA-SHAKE-128f", 240, BOTH, 20, flags="-DPICO_VARIANT_shake_128f"),
    S("slhdsa_bench",  "SLH-DSA-SHA2-192f",  300, BOTH, 25, flags="-DPICO_VARIANT_sha2_192f"),
    S("slhdsa_bench", "SLH-DSA-SHAKE-192f", 300, BOTH, 25, flags="-DPICO_VARIANT_shake_192f"),
    S("slhdsa_bench",  "SLH-DSA-SHA2-256f",  420, BOTH, 30, flags="-DPICO_VARIANT_sha2_256f"),
    S("slhdsa_bench", "SLH-DSA-SHAKE-256f", 420, BOTH, 30, flags="-DPICO_VARIANT_shake_256f"),
    # --- SLH-DSA 's' (small sig, minutes/sign) ---
    S("slhdsa_bench",  "SLH-DSA-SHA2-128s",  600,  BOTH, 20, flags="-DPICO_VARIANT_sha2_128s"),
    S("slhdsa_bench", "SLH-DSA-SHAKE-128s", 600,  BOTH, 20, flags="-DPICO_VARIANT_shake_128s"),
    S("slhdsa_bench",  "SLH-DSA-SHA2-192s",  900,  BOTH, 25, flags="-DPICO_VARIANT_sha2_192s"),
    S("slhdsa_bench", "SLH-DSA-SHAKE-192s", 900,  BOTH, 25, flags="-DPICO_VARIANT_shake_192s"),
    S("slhdsa_bench",  "SLH-DSA-SHA2-256s", 1500,  BOTH, 30, flags="-DPICO_VARIANT_sha2_256s"),
    S("slhdsa_bench", "SLH-DSA-SHAKE-256s",1500,  BOTH, 30, flags="-DPICO_VARIANT_shake_256s"),
    # --- SQIsign round 3 (the-sqisign "third-round version"): ref build, 32-bit field arithmetic (no GMP), as a
    #     precompiled library (sqisign_bench/make_sqisign_lib.sh; its KATs match the official ones). No heap; the big
    #     stack is the host-measured peak + margin. Signing takes minutes on the M0+: few iterations, long timeouts.
    S("sqisign_bench", "SQIsign-I round 3",   1800, BOTH, 128, flags="-DSQISIGN_LVL1 -DBIG_STACK_BYTES=131072u -DITERS=5"),
    S("sqisign_bench", "SQIsign-III round 3", 3600, BOTH, 168, flags="-DSQISIGN_LVL3 -DBIG_STACK_BYTES=172032u -DITERS=3"),
    S("sqisign_bench", "SQIsign-V round 3",   7200, BOTH, 216, flags="-DSQISIGN_LVL5 -DBIG_STACK_BYTES=221184u -DITERS=3"),

    # === RP2350-ONLY "candidates" =========================================
    # Size-feasible on the 520 KB RP2350 but TOO BIG for the 264 KB RP2040, so they are
    # gated off on RP2040 and only attempted on RP2350 with --candidates. They are NOT
    # yet hardware-validated. cat5 of SDitH exceeds even 520 KB and is omitted.
    # SDitH v3 (round 3, Aug 2026; VOLE-in-the-head): sign needs a 335 KB scratch buffer at cat 1 fast (959 KB short),
    # verify 329 KB: not on the RP2040. Its GF(2^128) code also uses __uint128_t, which arm-none-eabi-gcc lacks on 32-bit
    # targets, so even the RP2350 needs a {u64 lo, hi} port first. Recorded, not built.
    S("sdith_bench", "SDitH-cat1-fast round 3",  1800, (), 335, tier="infeasible",
      note="sign scratch 335 KB > RP2040 SRAM; RP2350 also needs a 32-bit port of its __uint128_t GF(2^128) code"),
    # FAEST 3.0 (round 3): one src (faest_bench/update_src.sh), -DPICO_VARIANT_<v> picks the set. Host peaks: sign heap
    # 341 KB (128f), 267 KB (EM-128f), 981 KB (192f), 1,587 KB (256f); stack under 7 KB. RP2350 only, and only the 128 sets.
    S("faest_bench", "FAEST-128f round 3",     3600, ("rp2350",), 345, tier="candidate",
      note="sign heap 341 KB > RP2040 SRAM", flags="-DPICO_VARIANT_128f"),
    S("faest_bench", "FAEST-EM-128f round 3",  3600, ("rp2350",), 270, tier="candidate",
      note="sign heap 267 KB > RP2040 SRAM", flags="-DPICO_VARIANT_em_128f"),
    S("faest_bench", "FAEST-192f round 3",     5400, (), 981, tier="infeasible", note="sign heap 981 KB > 520 KB",
      flags="-DPICO_VARIANT_192f"),
    S("faest_bench", "FAEST-256f round 3",     7200, (), 1587, tier="infeasible", note="sign heap 1,587 KB > 520 KB",
      flags="-DPICO_VARIANT_256f"),
]

# ---------------------------------------------------------------------------
# mqtt_tls_bench: credentials in, host-format results out
MQTT_ENV = ("WIFI_SSID", "WIFI_PASS", "BROKER")
MQTT_BASE_PORT = 18830  # ./run_all.sh --serve-broker
MQTT_R3_PORT = 20830    # its round 3 broker (MAYO / SNOVA certificates in certs/round3)

def cert_dir(sig):
    """a certificate set's folder and its broker's base port: round 3 sets (MAYO / SNOVA) are in certs/round3"""
    sys.path.insert(0, os.path.join(ROOT, "network"))
    from mqtt_bench import SIGS_R3
    return (os.path.join(ROOT, "certs", "round3", sig), MQTT_R3_PORT) if sig in SIGS_R3 else (os.path.join(ROOT, "certs", sig), MQTT_BASE_PORT)

def mqtt_secrets(sig, gen):
    """mt_secrets.h in gen/: Wi-Fi + broker from the environment, certs/<sig>'s CA, client cert and key as DER,
    the broker's ports for sig. Returns why it can't (a status), else None. Deleted after the compile."""
    d, base = cert_dir(sig)
    from mqtt_bench import port_of
    if not all(os.path.exists(os.path.join(d, f)) for f in ("CA.crt", "client.crt", "client.key")):
        return f"NO_CERTS: {d} (run gen_certs.sh, or rsync the broker machine's certs/)"
    def der(f):  # PEM (certificate, CRL, key) -> DER
        body = "".join(ln for ln in open(os.path.join(d, f)).read().splitlines() if ln and not ln.startswith("-----"))
        return base64.b64decode(body)
    out = [f"#define {k} {json.dumps(os.environ[k])}" for k in MQTT_ENV]  # a JSON string is a C string literal
    out += [f"#define PORT_PLAIN {MQTT_BASE_PORT}", f"#define PORT_TLS {port_of(base, sig, 'TLS')}",
            f"#define PORT_MTLS {port_of(base, sig, 'mTLS')}"]
    blobs = [("CA_DER", der("CA.crt")), ("CRT_DER", der("client.crt")), ("KEY_DER", der("client.key"))]
    if sig.startswith("DEPLOY"):  # a deployment firmware: its CRL, the refused certificates' ports, NTP
        if not os.path.exists(os.path.join(d, "CA.crl")):
            return f"NO_CERTS: {d}/CA.crl (DEPLOY_SIGS=all gen_certs.sh --deploy <broker IP>, then copy certs/)"
        out += [f"#define PORT_REVOKED {port_of(MQTT_BASE_PORT, sig, 'revoked')}",
                f"#define PORT_EXPIRED {port_of(MQTT_BASE_PORT, sig, 'expired')}",
                f"#define NTP_SERVER {json.dumps(os.environ.get('NTP_SERVER', 'pool.ntp.org'))}"]
        blobs += [("CRL_DER", der("CA.crl"))]
    if sig == "DEPLOY":  # + the broker's certificate, the update key, the old root (the full firmware)
        old = os.path.join("..", "ECDSAP256", "CA.crt")
        if not all(os.path.exists(os.path.join(d, f)) for f in ("server.crt", "update.pub", old)):
            return f"NO_CERTS: {d} (gen_certs.sh --deploy <broker IP>) and certs/ECDSAP256 (the old root)"
        blobs += [("SRV_DER", der("server.crt")), ("OLD_CA_DER", der(old)),
                  ("UPD_PUB", open(os.path.join(d, "update.pub"), "rb").read())]
    for name, b in blobs:
        out.append(f"static const unsigned char {name}[] = {{{','.join(map(str, b))}}};")
    os.makedirs(gen, exist_ok=True)
    with open(os.path.join(gen, "mt_secrets.h"), "w") as f:
        f.write("// generated by run_benchmarks.py for this build only\n#pragma once\n" + "\n".join(out) + "\n")
    return None

def hs_wrap_flags(sketch):
    """-Wl,--wrap=<f> for every WRAP(<cat>, <f>, ...) line of the sketch's hs_timing.c"""
    src = open(os.path.join(sketch, "hs_timing.c")).read()
    return " ".join(f"-Wl,--wrap={f}" for f in re.findall(r"^WRAP\(HS_\w+, (\w+),", src, re.M))

def mqtt_blocks(txt):
    """mqtt_tls_bench's '#block <stage> <mode> [<scheme> <up|down> | <group>]' .. '#end' sections -> [dict(stage,
    mode, aead, dir, lib, suite, err, heap, rows, msgs)]: rows / msgs as the host's run_timer() returns them.
    aead = the third word: the pipeline's scheme, or the sweep's key-exchange group."""
    blocks, cur = [], None
    def close(b):  # a block cut off (hang, reset, Ctrl-C) keeps its rows, with the reason as its error
        body = b.pop("body")
        b["rows"] = list(csv.DictReader(x for x in body if not x.startswith(("msg", "kex", "whole"))))
        b["msgs"] = list(csv.DictReader(x for x in body if x.startswith("msg")))
        b["wholes"] = list(csv.DictReader(x for x in body if x.startswith("whole")))
        b["kexs"] = list(csv.DictReader(x for x in body if x.startswith("kex")))
        blocks.append(b)
    for ln in txt.splitlines() + ["=== end of capture"]:
        if cur is not None and (ln.startswith("#block ") or ln.startswith("===")):
            n = sum(1 for x in cur["body"][1:] if x[:1].isdigit())
            cur["err"] = cur["err"] or f"output stopped after {n} recorded connections (board hung, reset or run interrupted)"
            close(cur); cur = None
        if ln.startswith("#block "):
            stage, mode, aead, d = (ln.split()[1:] + ["", ""])[:4]
            cur = dict(stage=stage, mode=mode, aead=aead, dir=d, lib="", suite="", err=None, heap="", stack="", body=[])
        elif ln.startswith("#watchdog ") and blocks:  # after the reboot: the block that hung, by its label
            name = (ln[len("#watchdog "):].split(":")[0].split() + ["", ""])[:4]
            hung = next((b for b in reversed(blocks) if [b["stage"], b["mode"], b["aead"], b["dir"]] == name), None)
            if hung:
                where = re.search(r"hung during (.+?) \(connection (-?\d+)\)", ln)
                hung["err"] = (f"hung during {where[1]} after {len(hung['rows'])} recorded connections (watchdog reset)"
                               if where else f"hung after {len(hung['rows'])} recorded connections (watchdog reset)")
        elif cur is None:
            continue
        elif ln == "#end":
            close(cur); cur = None
        elif ln.startswith("#"):
            k, _, v = ln[1:].partition(" ")
            cur["aead_label" if k == "aead" else k] = v  # '#aead <description>': the scheme's name stays the #block's
        else:
            cur["body"].append(ln)
    # a reset that isn't the watchdog's starts the plan over: keep each block's fullest run, not both
    best = {}
    for b in blocks:
        k, n = (b["stage"], b["mode"], b["aead"], b["dir"]), len(b["rows"]) + len(b["msgs"]) + len(b["kexs"])
        if k not in best or n >= best[k][0]:
            best[k] = (n, b)
    return [b for _, b in best.values()]

def save_mqtt(blocks, txt, family, sig, fqbn):
    """results/{mqtt_mtls,pipeline}_{summary,raw}_pico_<board>.csv + meta, in the host's columns (its summarize()),
    so collate_results.py reads them as a two-machine run. This signature's rows (and the plain reference)
    replace earlier ones; other signatures' stay."""
    from pathlib import Path
    import mqtt_bench as bmm  # on sys.path since mqtt_secrets()
    res, tag = Path(ROOT, "results"), f"pico_{family}{RUN_TAG}"
    kv = lambda prefix: dict(re.findall(r"(\w+)=(\S+)", next((ln for ln in txt.splitlines() if ln.startswith(prefix)), "")))
    cfg, wifi = kv("#config "), kv("#wifi ")
    certs = (bmm.der_bytes(Path(cert_dir(sig)[0], "server.crt")), bmm.der_bytes(Path(cert_dir(sig)[0], "client.crt")))
    res.mkdir(exist_ok=True)
    for stage, stem, rawname in (("connect", "mqtt_mtls", "raw"), ("pipeline", "pipeline", "msgs_raw")):
        summary, raw = [], []
        for b in (b for b in blocks if b["stage"] == stage):
            plain = b["mode"] == "plain"
            common = dict(Board=family, Library="none" if plain else "wolfSSL",
                          Signature="(plain MQTT reference)" if plain else sig, Group="" if plain else "X25519MLKEM768",
                          Mode=b["mode"], AEAD=b["aead"], Direction={"up": "uplink", "down": "downlink"}.get(b["dir"], ""),
                          TLS_suite=b["suite"],
                          status="OK" if not b["err"] else f"PARTIAL: {b['err']}" if b["rows"] else b["err"],
                          server_cert_B=None if plain else certs[0],
                          client_cert_B=None if plain or b["mode"].startswith("TLS") else certs[1], library_version=b["lib"])
            free = [int(r["free_heap_B"]) for r in b["rows"] if r.get("free_heap_B")]
            # a block cut off by a hang keeps what it measured, as PARTIAL (its rows are complete connections)
            summary.append(dict(bmm.summarize(common, b["rows"], b["msgs"], b.get("wholes", [])) if b["rows"] else dict(common, n=0),
                                peak_heap_B=b["heap"], stack_peak_B=b["stack"], free_heap_first_B=free[0] if free else "",
                                free_heap_last_B=free[-1] if free else ""))
            raw += [dict(Board=family, Library=common["Library"], Signature=common["Signature"], Mode=b["mode"],
                         AEAD=common["AEAD"], Direction=common["Direction"], **r)
                    for r in (b["msgs"] if stage == "pipeline" else b["rows"])]
        if not summary:
            continue
        key = lambda r: (r["Library"], r["Signature"], r["Mode"], r.get("AEAD", ""), r.get("Direction", ""))
        fresh = {key(r) for r in summary}
        for name, new in ((f"{stem}_summary_{tag}.csv", summary), (f"{stem}_{rawname}_{tag}.csv", raw)):
            old = list(csv.DictReader(open(res / name))) if (res / name).exists() else []
            bmm.write_csv(res / name, [r for r in old if key(r) not in fresh] + new)
        meta = dict(board=family, fqbn=fqbn, role="client", broker=f"{os.environ['BROKER']}:{MQTT_BASE_PORT}",
                    broker_local=False, group="X25519MLKEM768", modes="plain,tls,mtls",
                    messages=int(cfg.get("messages", 0)) if stage == "pipeline" else 0,
                    payload_B=int(cfg.get("payload_B", 51)), wifi=wifi, config=cfg,
                    started=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        (res / f"{stem}_meta_{tag}.json").write_text(json.dumps(meta, indent=2))
    save_sweep([b for b in blocks if b["stage"] == "sweep"], res, tag, sig, family, fqbn, cfg)
    save_kex([b for b in blocks if b["stage"] == "kex"], res, tag, family, fqbn, cfg, modes=sig == "DEPLOY")
    save_deploy([b for b in blocks if b["stage"] in ("refuse", "ta", "fcnt")], res, tag, family, sig)
    lib = next((b["lib"] for b in blocks if b["lib"].startswith("wolfSSL")), "")
    if lib:  # the KEM-exchange firmware prints no #lib line: keep the version the other sketches recorded
        (res / f"versions_{tag}.json").write_text(json.dumps(dict(board=family, fqbn=fqbn, wolfssl=lib[8:]), indent=2))
    print(f"    MQTT rows: {res}/{{mqtt_mtls,pipeline}}_summary_{tag}.csv")

SWEEP_COLS = ("mode,sig,group,n,mean_ms,median_ms,std_ms,min_ms,max_ms,p90_ms,p99_ms,ops_s,hs_tx_B,hs_rx_B,hs_B,"
              "writes,reads,tx_segs,rx_segs,wire_tx_B,wire_rx_B,wire_B,status").split(",")

def save_sweep(blocks, res, tag, sig, family, fqbn, cfg):
    """the sweep blocks -> results/tls_handshake_pure_<tag>.csv + meta, as tls_sweep.sh writes them (its
    summarize(): tls_ms stats, median bytes and socket calls; no TCP segment counts on the Pico). This signature's
    rows replace earlier ones; other signatures' stay."""
    if not blocks:
        return
    import mqtt_bench as bmm
    new = []
    for b in blocks:
        t = sorted(float(r["tls_ms"]) for r in b["rows"])
        row = dict.fromkeys(SWEEP_COLS, "") | dict(mode=b["mode"], sig=sig, group=b["aead"], n=len(t),
            status="OK" if not b["err"] else f"PARTIAL: {b['err']}" if t else b["err"])
        if t:
            n, mean = len(t), statistics.fmean(t)
            md = lambda k: int(statistics.median(int(r[k]) for r in b["rows"]))
            row.update(mean_ms=round(mean, 4), median_ms=round(statistics.median(t), 4),
                       std_ms=round(statistics.pstdev(t), 4), min_ms=t[0], max_ms=t[-1], p90_ms=t[int(n * .9)],
                       p99_ms=t[int(n * .99)], ops_s=round(1e3 / mean, 1), hs_tx_B=md("hs_tx_B"), hs_rx_B=md("hs_rx_B"),
                       hs_B=md("hs_tx_B") + md("hs_rx_B"), writes=md("hs_writes"), reads=md("hs_reads"))
            for c in (c for c in bmm.HS_COLS if c in b["rows"][0]):  # the handshake's own crypto on the board
                v = statistics.median(float(r[c]) for r in b["rows"])
                row[c[:-3] + "_median_us" if c.endswith("_us") else c] = round(v, 1)
        new.append(row)
    name = res / f"tls_handshake_pure_{tag}.csv"
    old = [r for r in csv.DictReader(open(name))] if name.exists() else []
    bmm.write_csv(name, [r for r in old if r["sig"] != sig] + new)
    (res / f"tls_handshake_meta_{tag}.json").write_text(json.dumps(dict(
        board=family, fqbn=fqbn, role="client", broker=f"{os.environ['BROKER']}:{MQTT_BASE_PORT}", broker_local=False,
        groups=[b["aead"] for b in blocks if b["mode"] == "TLS"], iterations=int(cfg.get("sweep_iterations", 0)),
        warmup=int(cfg.get("sweep_warmup", 0)), started=time.strftime("%Y-%m-%dT%H:%M:%S%z")), indent=2))
    print(f"    sweep rows: {name}")

def save_deploy(blocks, res, tag, family, sig="DEPLOY"):
    """a deployment firmware's refuse / ta / fcnt blocks -> results/deploy_<tag>.csv: one row per block, its
    '#deploy k=v' fields, the reason a refused connection gave, and whether FCnt resumed past the reboot. This
    certificate set's rows replace earlier ones; other sets' stay (rows without Signature are DEPLOY's)."""
    if not blocks:
        return
    import mqtt_bench as bmm
    rows = [dict(Board=family, Signature=sig, block=" ".join(x for x in (b["stage"], b["mode"], b["aead"]) if x),
                 status="OK" if not b["err"] and b.get("deploy") else b["err"] or "no #deploy line",
                 reason=b.get("reason", ""), **dict(re.findall(r"(\w+)=(\S+)", b.get("deploy", ""))))
            for b in blocks]
    save, resume = (next((r for r in rows if r["block"] == f"fcnt plain {k}"), None) for k in ("save", "resume"))
    if save and resume:  # the same keys after the reboot, and FCnt past every frame sent before it
        resume["same_devaddr"] = int(save.get("devaddr") == resume.get("devaddr"))
    f = res / f"deploy_{tag}.csv"
    old = [r for r in csv.DictReader(open(f)) if (r.get("Signature") or "DEPLOY") != sig] if f.exists() else []
    bmm.write_csv(f, old + rows)
    print(f"    deployment checks: {f}")

def save_kex(blocks, res, tag, family, fqbn, cfg, modes=False):
    """the kex blocks -> results/kem_exchange_{summary,raw}_<tag>.csv + meta, as the host's --kex writes them (its
    kex_summary()). A KEM's rows replace earlier ones from the same build (library_version: the X25519 A/B stays).
    modes: the deployment firmware's, named "<KEM> <plain | mTLS | signed>"."""
    if not blocks:
        return
    import mqtt_bench as bmm
    summary, raw = [], []
    for b in blocks:
        kem = f"{b['aead']} {b['mode']}" if modes else b["aead"]
        s, r = bmm.kex_summary(family, kem, dict(re.findall(r"(\w+)=(\S+)", b.get("kem", ""))), b["kexs"], b["err"])
        summary.append(s)
        raw += [dict(x, library_version=s["library_version"]) for x in r]
    key = lambda r: (r["KEM"], r.get("library_version", ""))
    fresh = {key(r) for r in summary}
    for name, new in ((f"kem_exchange_summary_{tag}.csv", summary), (f"kem_exchange_raw_{tag}.csv", raw)):
        old = list(csv.DictReader(open(res / name))) if (res / name).exists() else []
        bmm.write_csv(res / name, [r for r in old if key(r) not in fresh] + new)
    (res / f"kem_exchange_meta_{tag}.json").write_text(json.dumps(dict(
        board=family, fqbn=fqbn, role="client", broker=f"{os.environ['BROKER']}:{MQTT_BASE_PORT}", broker_local=False,
        kems=[b["aead"] for b in blocks], exchanges=int(cfg.get("kex_iterations", 0)),
        warmup=int(cfg.get("kex_warmup", 0)), started=time.strftime("%Y-%m-%dT%H:%M:%S%z")), indent=2))
    print(f"    KEM exchange rows: {res}/kem_exchange_summary_{tag}.csv")

def sh(cmd, **kw):
    print("  $", " ".join(cmd)); return subprocess.run(cmd, **kw)

def list_ports():
    """the Pico's USB serial ports (Raspberry Pi's USB vendor ID): /dev/cu.usbmodem* (macOS), /dev/ttyACM* (Linux), COMn"""
    try:
        from serial.tools import list_ports as lp
        return sorted(p.device for p in lp.comports() if p.vid == 0x2E8A)
    except ImportError:
        return sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*"))

def detect_port(prev=None):
    for _ in range(40):
        ports = list_ports()
        if prev:
            new = [p for p in ports if p not in prev]
            if new: return new[0]
        if ports: return ports[0]
        time.sleep(0.5)
    return None

def bootsel_touch(port):
    """1200-baud 'touch' that drops a running Philhower sketch into BOOTSEL."""
    if not port: return
    try:
        import serial
        s = serial.Serial(port, 1200); time.sleep(0.3)
        try: s.dtr = False
        except Exception: pass
        s.close()
    except Exception as e:
        print("    (1200bps touch note:", e, ")")

def bootsel_drive(label):
    """where the BOOTSEL drive with this label is mounted (macOS /Volumes, Linux /media or /run/media, a Windows drive
    letter), else None"""
    if os.name == "nt":
        for d in "DEFGHIJKLMNOPQRSTUVWXYZ":
            try:
                with open(f"{d}:\\INFO_UF2.TXT", errors="replace") as f:
                    if label in f.read():
                        return f"{d}:\\"
            except OSError:
                pass
        return None
    hits = glob.glob(f"/Volumes/{label}") + glob.glob(f"/media/*/{label}") + glob.glob(f"/run/media/*/{label}")
    return hits[0] if hits else None

def mounted_bootsel():
    """Return (family, drive) for whichever board's BOOTSEL drive is mounted, else (None, None)."""
    for fam, b in BOARDS.items():
        if (vol := bootsel_drive(b["label"])):
            return fam, vol
    return None, None

def wait_for_any_bootsel(timeout=20):
    for _ in range(int(timeout * 2)):
        fam, vol = mounted_bootsel()
        if fam: return fam, vol
        time.sleep(0.5)
    return mounted_bootsel()

def detect_board(port):
    """Identify the connected board. Uses an already-mounted BOOTSEL drive if present,
    otherwise resets the running sketch into BOOTSEL via a 1200bps touch. Returns the
    family key ('rp2040' / 'rp2350') or None."""
    fam, vol = mounted_bootsel()
    if not fam:
        print("  no BOOTSEL drive mounted; resetting the board into BOOTSEL to identify it...")
        bootsel_touch(port or (list_ports() or [None])[0])
        fam, vol = wait_for_any_bootsel(20)
    if not fam:  # the drive can be invisible to this terminal (macOS Removable Volumes permission): ask the chip
        r = picotool("info", "-d")
        out = r.stdout if r else ""
        fam = "rp2350" if "RP2350" in out else "rp2040" if "RP2040" in out else None
        if fam:
            print(f"  BOOTSEL drive not visible here; picotool reports {fam.upper()}")
        return fam
    print(f"  BOOTSEL volume {vol}")
    return fam

def picotool_path():
    """arduino-pico's picotool (flashes over USB, no file system), else one on PATH"""
    hits = sorted(glob.glob(os.path.expanduser("~/Library/Arduino15/packages/rp2040/tools/pqt-picotool/*/picotool")) +
                  glob.glob(os.path.expanduser("~/.arduino15/packages/rp2040/tools/pqt-picotool/*/picotool")) +
                  glob.glob(os.path.expanduser("~/AppData/Local/Arduino15/packages/rp2040/tools/pqt-picotool/*/picotool.exe")))
    return hits[-1] if hits else shutil.which("picotool")

def picotool(*args, timeout=60):
    """run picotool; None when there is none"""
    pt = picotool_path()
    try:
        return subprocess.run([pt, *args], capture_output=True, text=True, timeout=timeout) if pt else None
    except subprocess.TimeoutExpired:
        return None

def in_bootsel(label):
    """the drive is mounted, or picotool reaches a board in BOOTSEL (the drive can be hidden from this terminal)"""
    if bootsel_drive(label):
        return True
    r = picotool("info")
    return bool(r) and r.returncode == 0

def force_bootsel(port, label, wait_s):
    """BOOTSEL for the next flash. The 1200-baud touch needs the running sketch's USB (picotool's forced reboot finds no
    reset interface on these builds). A sketch that hung with its USB dead (a fault, a stack overflow) ignores it, and
    before this every later sketch failed to flash too. So wait for a person to hold BOOTSEL and replug (wait_s, 0 =
    don't). liboqs_bench reboots itself into BOOTSEL after such a hang (its watchdog), so that wait is rare."""
    bootsel_touch(port)
    for _ in range(20):
        if in_bootsel(label):
            return True
        time.sleep(1)
    if wait_s:
        print(f"\a    !! the board doesn't answer on USB (its last sketch hung). Hold BOOTSEL and replug it "
              f"(or press RESET while holding BOOTSEL); waiting up to {wait_s // 60} min ...", flush=True)
        end = time.time() + wait_s
        while time.time() < end:
            if in_bootsel(label):
                return True
            time.sleep(2)
    return False

def picotool_load(uf2, why):
    r = picotool("load", "-x", uf2, timeout=120)
    if r and r.returncode == 0:
        return True, f"ok (picotool over USB; {why})"
    return False, f"{why}; picotool: {(r.stderr or r.stdout).strip().splitlines()[-1:] if r else 'not found'}"

def upload_uf2(uf2, label, port, wait_s=0):
    """Flash by byte-copying the .uf2 onto the BOOTSEL drive (a plain write, not shutil.copy: the FAT volume rejects
    metadata ops with EPERM on macOS); picotool over USB when the drive is hidden or refuses the write."""
    if not bootsel_drive(label) and not force_bootsel(port, label, wait_s):
        return False, "the board never entered BOOTSEL (hold BOOTSEL and replug it)"
    for _ in range(10):  # the drive mounts a few seconds after BOOTSEL starts
        if (vol := bootsel_drive(label)):
            break
        time.sleep(0.5)
    if not vol:  # in BOOTSEL (picotool sees it), but the drive is hidden from this terminal
        return picotool_load(uf2, "the BOOTSEL drive is not visible here")
    try:
        with open(uf2, "rb") as src, open(os.path.join(vol, os.path.basename(uf2)), "wb") as dst:
            dst.write(src.read()); dst.flush()
            try: os.fsync(dst.fileno())
            except Exception: pass
    except Exception as e:
        # the board flashes + reboots the instant the UF2 lands, unmounting the drive,
        # so write/close can raise even though the flash succeeded.
        time.sleep(1)
        if not bootsel_drive(label):
            return True, "ok (drive ejected after write = flashed)"
        # EPERM here is macOS privacy blocking this terminal app from removable volumes: picotool loads the
        # same UF2 over USB instead (the board is in BOOTSEL, so it's listening)
        ok, msg = picotool_load(uf2, f"the drive write failed: {e}")
        return ok, msg if ok else (msg + ". If it says 'Operation not permitted': System Settings > Privacy & "
                                   "Security > Files and Folders > <your terminal app> > Removable Volumes on, then reopen it")
    return True, "ok"

OP_RE = re.compile(r"\b(keygen|sign|verify)\b", re.I)
def _g(line, pat, cast=int, default=""):
    m = re.search(pat, line, re.I)
    try: return cast(m.group(1)) if m else default
    except Exception: return default

STOP = False  # Ctrl-C during a capture: keep what arrived, then finish (results, collate) without the rest

def open_serial(port, tries):
    """the board's serial port (port, else the first one listed), retrying once a second; None if it never opens"""
    import serial
    for _ in range(tries):
        try:
            p = port if port in list_ports() else (list_ports() or [port])[0]
            ser = serial.Serial(p, 115200, timeout=2, dsrdtr=True); ser.dtr = True
            return ser
        except Exception:
            time.sleep(1)
    return None

def capture(port, timeout, logpath, no_timeout=False, max_reconnects=8):
    global STOP
    rows, sizes, txt = {}, None, []
    log = open(logpath, "w")  # line by line: a hang or Ctrl-C still leaves the log
    ser = open_serial(port, 15)
    if ser is None:
        print("    !! could not open serial", port); return rows, sizes, False, ""
    saw_header = fault = False
    mhz = None
    reconnects = 0
    last = time.time()
    while True:
        if (not no_timeout) and (time.time() - last > timeout):
            print(f"    !! no new output for {timeout}s; moving on (use --no-timeout to wait)"); break
        try:
            line = ser.readline().decode("utf-8", "replace").rstrip()
        except KeyboardInterrupt:
            print("    !! Ctrl-C: keeping this sketch's output, skipping the rest"); STOP = True; break
        except Exception:
            try: ser.close()
            except Exception: pass
            ser = None
            if reconnects >= max_reconnects: break
            reconnects += 1
            print("    .. serial dropped (board reset?); reconnecting to read the fault report...")
            time.sleep(1)
            ser = open_serial(port, 12)
            if ser is None: break
            last = time.time(); continue
        if not line: continue
        last = time.time()
        txt.append(line); print("    |", line); log.write(line + "\n"); log.flush()
        if "===" in line and " on RP" in line:        # board-agnostic banner match (RP2040 / RP2350)
            saw_header = True
        if "MEMORY FAULT" in line or "HARDFAULTED" in line:
            fault = True
        if line.startswith("CPU clock: "):
            mhz = _g(line, r"CPU clock: (\d+)")
        if "sizes:" in line.lower():
            sizes = (_g(line, r"\bpk=(\d+)"), _g(line, r"\bsk=(\d+)"),
                     _g(line, r"\bsigMax=(\d+)"), _g(line, r"\bsig=(\d+)"))
        mo = OP_RE.search(line)
        if mo and "mean=" in line:
            op = mo.group(1).lower()
            rows[op] = dict(
                mean=_g(line, r"\bmean=(\d+)us"), median=_g(line, r"\bmedian=(\d+)us"),
                std=_g(line, r"\bstd=(\d+)us"),
                mean_cyc=_g(line, r"\bmean_cyc=(\d+)"), median_cyc=_g(line, r"\bmedian_cyc=(\d+)"),
                ops=_g(line, r"\bops/s=([\d.]+)", float))
            if mhz:  # the sketches print us x MHz as a 32-bit unsigned long: it wraps for ops over 21.5 s at 200 MHz
                for k in ("mean", "median"):
                    if rows[op][k] != "": rows[op][k + "_cyc"] = rows[op][k] * mhz
        if "=== done" in line and saw_header:
            break
    try:
        if ser: ser.close()
    except Exception: pass
    log.close()
    return rows, sizes, fault, "\n".join(txt)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port")
    ap.add_argument("--board", choices=list(BOARDS), help="force a board family, skip auto-detect")
    ap.add_argument("--fqbn", help="override the board's default FQBN")
    ap.add_argument("--candidates", action="store_true",
                    help="also attempt RP2350 size-feasible (unvalidated) extras")
    ap.add_argument("--only", help="comma list of folders to run")
    ap.add_argument("--skip", help="comma list of folders to skip")
    ap.add_argument("--no-upload", action="store_true", help="compile+capture only")
    ap.add_argument("--no-timeout", action="store_true", help="never give up (RSA keygen)")
    ap.add_argument("--bootsel-wait", type=int, default=900, help="seconds to wait for a manual BOOTSEL when a hung "
                    "board ignores the USB reset (0: fail that flash and move on)")
    ap.add_argument("--lib", help="comma list of libraries to run (substring): "
                    + ", ".join(sorted({lib for _, lib in LIB_BY_PREFIX})))
    ap.add_argument("--list", action="store_true", help="show what the filters select, then exit (no flashing)")
    ap.add_argument("--test", help="comma list: signature (pqc) or MQTT over TLS / mTLS + the LoRaWAN / AES / Ascon "
                    "pipeline over Wi-Fi (mqtt) sketches")
    ap.add_argument("--match", help="comma list of algorithm names to keep, e.g. ml-dsa-44,falcon,ascon "
                    "(case/punctuation-insensitive substring of the label)")
    # optimisation knobs; each one tags the label, so these rows sit next to the default ones in results.csv
    ap.add_argument("--keccak", choices=("xkcp",), help="liboqs_bench only: link liboqs with XKCP's assembler "
                    "Keccak (liboqs_bench/keccak_swap.sh; checked by tests/qemu_liboqs/run.sh)")
    ap.add_argument("--opt", choices=("O", "O2", "O3", "Ofast"), help="compiler level for the sketch and core "
                    "(arduino-pico default -Os); precompiled liboqs / wolfSSL keep their own -O3")
    ap.add_argument("--freq", type=int, help="CPU MHz (default RP2040 200, RP2350 150; the RP2040 study in the "
                    "README used 133)")
    ap.add_argument("--tag", help="name this run apart from the default one, e.g. pi_broker (the Pico against the "
                    "Pi's brokers): results/*_pico_<board>_<tag>.*, logs in pico/logs_<tag>/")
    args = ap.parse_args()
    if args.tag:
        global LOGDIR, RUN_TAG
        RUN_TAG, LOGDIR = f"_{args.tag}", os.path.join(HERE, f"logs_{args.tag}")

    os.makedirs(LOGDIR, exist_ok=True)
    initial_port = args.port or (list_ports() or [None])[0]

    # ---- detect (or accept) the board ----
    family = args.board or detect_board(initial_port)
    if not family:
        print("\n!! Could not identify the board. Put it in BOOTSEL (or pass --board rp2040|rp2350) and retry.")
        sys.exit(1)
    board  = BOARDS[family]
    fqbn   = args.fqbn or board["fqbn"]
    menu = [f"opt={dict(O='Optimize', O2='Optimize2', O3='Optimize3', Ofast='Fast')[args.opt]}"] if args.opt else []
    menu += [f"freq={args.freq}"] if args.freq else []
    if menu:
        fqbn += ":" + ",".join(menu)
    tag = (f" -{args.opt}" if args.opt else "") + (f" @{args.freq}MHz" if args.freq else "")
    drive  = board["label"]  # its BOOTSEL drive's label
    print(f"\nBoard: {board['name']}")
    print(f"  -> FQBN {fqbn} | BOOTSEL drive {drive} | SRAM {board['sram_kb']} KB\n")

    only = set(args.only.split(",")) if args.only else None
    libs = [x.strip().lower() for x in args.lib.split(",")] if args.lib else None
    match = [norm(x) for x in args.match.split(",")] if args.match else None
    skip = set(args.skip.split(",")) if args.skip else set()

    # ---- gate by capability, and SHOW what is prevented from flashing ----
    work, gated = [], []
    for s in SKETCHES:
        if only and s["folder"] not in only:        continue
        if libs and not any(l in lib_of(s) for l in libs):          continue
        if args.test and test_of(s) not in args.test.split(","):    continue
        if match and not any(m in norm(s["label"]) for m in match): continue
        if s["folder"] in skip:                      continue
        missing = [k for k in MQTT_ENV if not os.environ.get(k)] if s["folder"] == "mqtt_tls_bench" else []
        if s["boards"] and missing:  # exported in THIS shell; BROKER = the ./run_all.sh --serve-broker machine
            gated.append((s, "missing from the environment: " + ", ".join(missing))); continue
        if family not in s["boards"]:
            gated.append((s, s["note"] or f"won't fit {family} ({s['ws_kb']} KB > {board['sram_kb']} KB SRAM)")); continue
        if s["tier"] == "candidate" and not args.candidates:
            gated.append((s, f"candidate for {family} (use --candidates); {s['note']}")); continue
        if args.keccak and s["folder"] == "liboqs_bench" and not s["lib"]:  # the 0.16 library only
            s = dict(s, label=s["label"].replace("(liboqs)", "(liboqs+XKCP Keccak)"), lib="liboqs+xkcp")
        work.append(dict(s, label=s["label"] + tag) if tag else s)

    print(f"Will flash {len(work)} algorithm(s) capable on {family}:")
    for s in work: print(f"   + {s['label']:<40} [{lib_of(s)}] ({s['ws_kb'] or '?'} KB)")
    if gated:
        print(f"\nSkipping {len(gated)} not capable / not selected on {family}:")
        for s, why in gated: print(f"   - {s['label']:<22} {why}")
    print(f"\nLogs -> {LOGDIR}\n")

    if args.list:
        return
    for r3 in {s["lib"] == R3 for s in work if s["folder"] in ("liboqs_bench", "uov_bench") or "-DMT_KEX_ONLY" in s["flags"]
               or s["lib"] == R3}:
        print(f"Preparing the liboqs{' round 3' if r3 else ''} Arduino library (liboqs_bench/make_liboqs_lib.sh) ...")
        sh([BASH, os.path.join(SKETCH_DIR, "liboqs_bench", "make_liboqs_lib.sh")],
           env=dict(os.environ, LIBOQS_KECCAK=args.keccak or "", LIBOQS_ROUND="3" if r3 else ""))
    if any(s["folder"] == "uov_bench" for s in work):
        print("Preparing the UOV-Ip round 3 key pair (uov_bench/make_uov_keys.sh) ...")
        sh([BASH, os.path.join(SKETCH_DIR, "uov_bench", "make_uov_keys.sh")])
    if any(s["folder"] == "sqisign_bench" for s in work):
        print("Preparing the SQIsign Arduino library (sqisign_bench/make_sqisign_lib.sh) ...")
        sh([BASH, os.path.join(SKETCH_DIR, "sqisign_bench", "make_sqisign_lib.sh")])
    if any(s["folder"] in ("wolfssl_bench", "mqtt_tls_bench") for s in work):
        print("Preparing the wolfSSL Arduino library (wolfssl_bench/make_wolfssl_lib.sh) ...")
        sh([BASH, os.path.join(SKETCH_DIR, "wolfssl_bench", "make_wolfssl_lib.sh")])

    csv_path = os.path.join(LOGDIR, "results.csv")
    hdr = ["Board","Algorithm","pk","sk","sigMax","sig"]
    for op in ("keygen","sign","verify"):
        hdr += [f"{op}_mean_us", f"{op}_median_us", f"{op}_std_us",
                f"{op}_mean_cyc", f"{op}_median_cyc", f"{op}_ops_s"]
    hdr += ["status", "Library"]
    # merge, don't overwrite: keep earlier rows except the ones this run re-measures
    rerun = {(family, s["label"]) for s in work}
    kept = []
    if os.path.exists(csv_path):
        with open(csv_path, newline="") as f:
            kept = [r for r in csv.DictReader(f) if (r.get("Board"), r.get("Algorithm")) not in rerun]
    cf = open(csv_path, "w", newline=""); cw = csv.writer(cf)
    cw.writerow(hdr)
    cw.writerows([r.get(h) or "" for h in hdr] for r in kept); cf.flush()

    def row(label, sizes=("","","",""), rows=None, status="NO_OUTPUT", lib=""):
        rows = rows or {}
        g, s, v = rows.get("keygen", {}), rows.get("sign", {}), rows.get("verify", {})
        cols = lambda d: [d.get("mean",""), d.get("median",""), d.get("std",""),
                          d.get("mean_cyc",""), d.get("median_cyc",""), d.get("ops","")]
        cw.writerow([family, label, *sizes] + cols(g) + cols(s) + cols(v) + [status, lib]); cf.flush()

    for s in work:
        folder, label, timeout = s["folder"], s["label"], s["timeout"]
        path = os.path.join(SKETCH_DIR, folder)
        print(f"=== {label}  ({folder})  timeout={timeout}s ===")
        if not os.path.isdir(path):
            print("    !! missing folder, skipping"); row(label, lib=lib_of(s), status="MISSING_FOLDER"); continue

        # key the output/build dir by LABEL when -D flags are used, so multiple parameter sets that
        # share one src folder (e.g. slhdsa_bench) don't collide or reuse each other's cached objects.
        key = re.sub(r"[^A-Za-z0-9_.-]+", "_", label) if s.get("flags") else folder
        outdir = os.path.join(tempfile.gettempdir(), "pico_uf2", key)
        shutil.rmtree(outdir, ignore_errors=True)
        wifi = s["folder"] == "mqtt_tls_bench"
        flags = s.get("flags", "")
        if wifi:  # the W board (Wi-Fi) + a generated header with the credentials and certificates
            sig = re.search(r"-DMT_SIG=(\w+)", flags)[1]
            why = mqtt_secrets(sig, os.path.join(outdir, "gen"))
            if why:
                print("    !!", why); row(label, lib=lib_of(s), status=why); continue
            flags += f" -I{os.path.join(outdir, 'gen')}"
        build_fqbn = re.sub(r"^(rp2040:rp2040:rpipico2?)\b", r"\1w", fqbn) if wifi else fqbn
        if "-DMT_DEPLOY" in flags:  # LittleFS (trust anchor, LoRaWAN state): a 64 KB flash filesystem
            build_fqbn += ":flash=" + ("4194304_65536" if "rpipico2" in build_fqbn else "2097152_65536")
        cmd = ["arduino-cli","compile","--fqbn",build_fqbn,"--output-dir",outdir]
        if flags:
            cmd += ["--build-path", os.path.join(outdir, "build"),
                    "--build-property", f"compiler.c.extra_flags={flags}",
                    "--build-property", f"compiler.cpp.extra_flags={flags}"]
        if s["folder"] == "uov_bench":  # the host-made key pair (make_uov_keys.sh)
            flags += f" -I{os.path.join(os.path.dirname(WOLF_LIBS), 'uov-r3')}"
        if s["folder"] in ("wolfssl_bench", "liboqs_bench", "mqtt_tls_bench", "sqisign_bench", "uov_bench"):
            cmd += ["--libraries", libraries(s)]
        if wifi:  # time the handshake's own crypto per connection: wolfSSL's calls go through hs_timing.c
            cmd += ["--build-property", "compiler.c.elf.extra_flags=" + hs_wrap_flags(path)]
        cmd += [path]
        r = sh(cmd)
        if wifi:
            shutil.rmtree(os.path.join(outdir, "gen"), ignore_errors=True)
        if r.returncode != 0:
            row(label, lib=lib_of(s), status="COMPILE_FAIL"); continue

        port = args.port or (list_ports() or [None])[0]
        if not args.no_upload:
            uf2 = (glob.glob(os.path.join(outdir, "*.uf2")) or [None])[0]
            if not uf2:
                print("    !! no .uf2 produced"); row(label, lib=lib_of(s), status="NO_UF2"); continue
            prev = list_ports()
            ok, msg = False, ""
            for attempt, wait_s in enumerate((0, args.bootsel_wait)):  # the second attempt may wait for a person
                ok, msg = upload_uf2(uf2, drive, args.port or (prev[0] if prev else None), wait_s)
                if ok: break
                print(f"    !! flash attempt {attempt+1} failed ({msg})")
            if not ok:  # keep the reason: a board not in BOOTSEL and a blocked volume need different fixes
                row(label, lib=lib_of(s), status=f"UPLOAD_FAIL: {msg}"); continue
            if wifi:  # the firmware holds the Wi-Fi password and the client key
                shutil.rmtree(outdir, ignore_errors=True)
            print("    flashed; waiting for the board to reboot + enumerate...")
            time.sleep(4)
            port = args.port or detect_port(prev=prev) or (list_ports() or [None])[0]

        if not port:
            print("    !! no serial port found"); row(label, lib=lib_of(s), status="NO_PORT"); continue

        # mqtt_tls_bench: every watchdog reboot moves on to the next block, so allow one per block (83), not 8
        rows, sizes, fault, txt = capture(port, timeout, os.path.join(LOGDIR, key + ".log"),
                                          no_timeout=args.no_timeout, max_reconnects=100 if wifi else 8)
        sizes = (list(sizes or ()) + ["","","",""])[:4]
        g, sg, v = rows.get("keygen"), rows.get("sign"), rows.get("verify")
        started  = ">>>" in txt
        any_iter = ("  iter " in txt) or ("[iter" in txt)
        if "OUT OF MEMORY" in txt:    status = "RUNTIME_MEMORY_FAIL"
        elif "STACK OVERFLOW" in txt: status = "STACK_OVERFLOW"
        elif fault:                   status = "FAULT"
        elif g and sg and v:          status = "OK"
        elif rows:                    status = "PARTIAL"
        elif started and not any_iter:status = "STUCK_NO_PROGRESS(likely mem/stack)"
        elif started or any_iter:     status = "PARTIAL"
        else:                         status = "NO_OUTPUT"
        if not wifi and status != "OK" and in_bootsel(drive):  # liboqs_bench's watchdog / fault handler took it there
            status += " - hung: the board reset itself into BOOTSEL"
        if wifi:
            blocks = mqtt_blocks(txt)
            fatal = next((ln[7:] for ln in txt.splitlines() if ln.startswith("#fatal ")), None)
            errs = [b["err"] for b in blocks if b["err"]]
            status = ("FAULT" if fault else fatal or ("NO_OUTPUT" if not blocks else
                      f"OK ({len(blocks)} MQTT blocks)" if not errs else f"{len(errs)}/{len(blocks)} blocks failed: {errs[0]}"))
            if blocks:
                save_mqtt(blocks, txt, family, sig, build_fqbn)
        row(label, sizes, rows, status, lib_of(s))
        print(f"    -> {status}\n")
        if STOP:
            break

    cf.close()
    print(f"\nDONE on {family}. Summary CSV: {csv_path}")
    print("Per-algo serial logs are alongside it in", LOGDIR)

if __name__ == "__main__":
    main()
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "collate_results.py")])  # results/all_results.csv
