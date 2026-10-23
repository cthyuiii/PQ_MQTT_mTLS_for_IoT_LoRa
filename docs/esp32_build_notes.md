# PQC Signatures on the ESP32 (ESP32-WROOM-32UE) — Build Notes

The ESP32 port of the Pico's Stage 1 sketches (11 Oct 2026) and of its Stage 2 firmware (run 22-23 Oct 2026). How each sketch was brought up on the RP2040, and what failed there, is in [pico_build_notes.md](pico_build_notes.md).

The Stage 1 sketches and the Pico W's Stage 2 firmware (`mqtt_tls_bench`) also build for a classic ESP32 (Xtensa
LX6 dual core @ 240 MHz, ~320 KB DRAM, no PSRAM; `arduino-esp32` 3.3.12, FQBN `esp32:esp32:esp32`). Run them with
`python pico/run_benchmarks.py --board esp32` (Stage 1 results in `pico/logs_esp32/`; Stage 2 below). The Pico builds
are meant to be unchanged: every board call goes through `pico/libraries/board_compat/src/board_compat.h`, which maps to the same
`rp2040.*` calls on arduino-pico.

**What differs from the Pico, and how each sketch deals with it**

- **Board calls.** `rp2040.hwrand32()` / `getFreeStack()` / `getFreeHeap()` and `F_CPU` became `board_hwrand32()`,
  `board_free_stack()`, `board_free_heap()`, `board_cpu_mhz()`; banners print `BOARD_CHIP` (`BOARD_FAMILY` in the
  big-stack sketches, "RP" on the Pico as before). On the ESP32 `board_free_stack()` is the loop task's high-water
  mark (least free so far), not the free stack now.
- **`loop()` is a FreeRTOS task with an 8 KB stack.** Each sketch sets its own with `BOARD_LOOP_STACK(bytes)` (a no-op
  on the Pico). The largest free block on a WROOM-32 is ~108–110 KB, so nothing above that can start.
- **Big stack (`bigstack.h`, `liboqs_bench`).** Xtensa's windowed registers rule out the hand-written SP switch:
  ESP-IDF's `esp_execute_shared_stack_function` runs the operation on the buffer instead. The buffer is a heap block
  (`heap_caps_aligned_alloc`), not static: the linker caps static DRAM near 136 KB, so QR-UOV's 88 / 104 KB stacks
  overflowed `dram0_0_seg` as static arrays. That function **fills the whole stack with 0xA5 before every call**, over
  any paint of ours: with the Pico's 0x5A pattern every op read as a full stack (a false `STACK OVERFLOW`). The ESP32
  scans for 0xA5. Check: QR-UOV's peaks match the host-measured ones in `qruov_bench.ino` within ~2 KB.
- **No BOOTSEL, no RP watchdog.** esptool flashes over the USB-serial bridge (`arduino-cli upload`); the runner pulses
  EN through RTS before reading, so each report starts at boot. The Pico-only fault / watchdog code (`isr_hardfault`,
  `reset_usb_boot`, `watchdog_*`) is compiled out. A panic ("Guru Meditation") is recorded as `FAULT`; the runner
  stops at the end of the first panic dump, as the board then reboots into the same panic forever.
- **BearSSL** (ECDSA, RSA) is in arduino-pico's core, not arduino-esp32's. `ecdsa_bench/make_bearssl_lib.sh` packages
  the same code: `earlephilhower/bearssl-esp8266` at `aca1383`, the commit arduino-pico 6.1.1 pins. The sketches
  include `<bearssl.h>` on the ESP32, as arduino-cli finds libraries only by the headers at the top of `src/`.
- **liboqs** (`make_liboqs_lib.sh`) builds `src/esp32/liboqs.a` with arduino-esp32's Xtensa GCC and the code
  generation flags the core uses for every sketch (`-mlongcalls`, the PSRAM cache workaround, no hardware atomics).
  Each target is built when its core's toolchain is installed.
- **wolfSSL.** `settings.h`'s Arduino-ESP32 defaults turn the cache-resistant code off (`WC_NO_CACHE_RESISTANT`; the
  Pico's ARM branch doesn't), which also breaks the small RSA build (`addr_mask`). `wolfssl_user_settings.h` skips
  those defaults on the ESP32 (`NO_ARDUINO_DEFAULT`) and sets what the ARM branch sets, plus `WOLFSSL_LWIP` for
  `wolfio.h`'s socket types. The SP math for ECDSA / RSA is portable C on the ESP32 (Cortex-M assembly on the Pico),
  so those wolfSSL rows don't compare like for like.
- **Windows hosts.** `make_wolfssl_lib.sh` checks wolfSSL out with LF (Git for Windows' `core.autocrlf=true` made its
  `$`-anchored perl patches miss 5 of 12 SNOVA constants); the library builders' CMake uses Ninja, which can come from
  the repo's `.venv` (`pip install ninja`). Ed25519 needs `arduino-cli lib install Crypto`, as on the Pico.

**Not on the ESP32 (memory):** ML-DSA-87 through liboqs (faulted on a 96 KB stack; mldsa-native's default build of
the same set overflows 106 KB, so `mldsa_bench` runs it as `-DMLD_CONFIG_REDUCE_RAM`, its own row), MAYO-1/2/3 (237 KB+
of stack), UOV-pkc (238 KB+ secret keys), QR-UOV-1q7L10 (160 KB stack), SQIsign (128–216 KB stacks), FAEST (267 KB+
heap), SDitH (335 KB). In Stage 2, Falcon-1024 as the device's own certificate (mTLS: signing needs ~138 KB of
heap; below).

**Stage 2, the pipeline and the deployment checks (`mqtt_tls_bench`)**

The same firmware as the Pico W's, over the ESP32's Wi-Fi, against the same brokers: every block, row and log line is
the Pico's, so `run_benchmarks.py --board esp32 --test mqtt` summarises them with the host's code into
`results/*_pico_esp32.*` (`*_pico_esp32_<tag>.*` with `--tag`; WIFI_SSID, WIFI_PASS and BROKER in the environment,
`certs/` copied from the broker machine).
What the ESP32 build changes:

- **Watchdog.** The RP2040's 8 s hardware watchdog becomes the task watchdog on the loop task (8 s, a panic and reboot
  when it fires). Its scratch registers, which tell the next boot which block and step hung, become `RTC_NOINIT` memory,
  which a watchdog, panic or software reset keeps. A crash (any panic, not only the watchdog's) also moves on to the next
  block, as `#watchdog <block>: crashed during <step>`; the runner logs the panic dump, keeps it out of the parsed rows,
  and stops only if the board crashes before any block at every boot. SNOVA's long signatures are covered by a watchdog
  *user* that a timer feeds (10 × 2 s, as the Pico's repeating timer), since the task watchdog is fed only by its task.
- **Stack.** The blocks run on a heap block through `esp_execute_shared_stack_function`, as in `bigstack.h`, taken at
  boot before Wi-Fi splits the heap (16 KB; 80 KB for the KEM exchange; SNOVA's 36–104 KB). `#stack` scans for the
  0xA5 fill.
- **Pipeline crypto.** AES, CMAC and GCM / CCM are the same BearSSL code (`make_bearssl_lib.sh`), still software `aes_ct`:
  the ESP32 has an AES engine, but it isn't used, so the rows compare the same code. Ascon is ascon-c's `esp32` C
  variant (`src/esp32/`) at the Pico's commit: its `asm_esp32` assembly still implements Ascon-128 v1.2, not NIST
  SP 800-232. Each board compiles only its own Ascon (`#if defined(__arm__)` / `__XTENSA__` around the files). The
  known-answer checks (CMAC, CCM, LoRaWAN, the SP 800-232 Ascon vector) pass on the board.
- **Handshake timing** (`hs_timing.c`, `-Wl,--wrap`) uses `esp_timer_get_time()`; the wraps link as on the Pico.
- **Wi-Fi, time, flash.** `WiFi.setSleep(false)` for the Pico's `noLowPowerMode()`; `configTime()` for its NTP client
  (the deployment checks); LittleFS on the spiffs partition. The runner builds with the Huge APP partition table (3 MB
  of program, 1 MB of LittleFS): the deployment and SNOVA builds are 1.21–1.30 MB, past the default table's 1.2 MB.
- **Randomness.** `esp_random()` is true random only while the radio runs: the LoRaWAN keys made before Wi-Fi starts
  use the bootloader's entropy source, switched off again before Wi-Fi needs the ADC.

**Stage 2 results (22-23 Oct 2026, `--tag pi`)**

Broker: a Raspberry Pi 4 (`./run_all.sh --serve-broker`) on the same home network; the ESP32 on 2.4 GHz Wi-Fi
(RSSI -40 to -84 dBm). Logs in `pico/logs_pi/`, summaries in `results/*_pico_esp32_pi.*`. The Pico W figures below
are its `pi_broker4` run: if that broker was a different Pi, its share of each handshake differs too, so the ratios
are approximate. Every Stage 2 firmware has run. Most failed blocks were the network: `tcp connect failed`, `error
state on socket` or `no echo from broker` in plain MQTT blocks as well, in runs of several blocks, and the first
attempt at five certificates failed at -84 dBm (the -32UE's antenna is external). Those builds were re-run.

- **ML-DSA-44: 36 of 41 blocks.** Connect (X25519MLKEM768, 50 each): plain MQTT 16 ms, TLS 832 ms and mTLS 938 ms of
  handshake. wolfSSL's heap peaks at 28.0 / 39.0 KB (TLS / mTLS); at least 193 KB stays free. The failures:
  - SecP256r1MLKEM512 and x25519_mlkem512, TLS and mTLS: the broker's fatal alert, as on the Pico (wolfSSL and
    oqs-provider give these two hybrids different TLS IDs).
  - SecP256r1MLKEM768 TLS stopped after 10 of 20 handshakes on `tcp connect failed`, a Wi-Fi drop; its mTLS block
    right after was complete.
- **The key-exchange sweep (ML-DSA-44, TLS handshake medians, 20 each; ESP32 / Pico W):**

  | Group | TLS | mTLS | The board's key-exchange crypto |
  |---|---|---|---|
  | ML-KEM-512 / 768 / 1024 | 162 / 176 / 157 ms (160 / 169 / 183) | 258 / 237 / 296 ms (347 / 322 / 356) | 9.5 / 14.5 / 21.5 ms (16.5 / 23.2 / 36.5) |
  | X25519MLKEM768 | 845 ms (284) | 948 ms (536) | 721 ms (139) |
  | SecP256r1MLKEM768 | 348 ms (282) | 456 ms (509) | 204 ms (126) |
  | SecP384r1MLKEM1024 | 819 ms (680) | 918 ms (879) | 671 ms (526) |
  | p384_mlkem768 / p521_mlkem1024 | 819 / 1,652 ms (– / 931) | 923 / 1,741 ms (852 / 1,127) | 664 / 1,470 ms |
  | x448_mlkem768 | 1,735 ms (587) | 1,840 ms (757) | 1,588 ms (427) |
  | X25519 | 816 ms (256) | 900 ms (462) | 707 ms (116) |
  | P-256 | 305 ms (240) | 414 ms (433) | 190 ms (103) |

  ML-KEM itself is faster on the ESP32; every curve is slower (see the open questions). The pure ML-KEM rows are
  short enough that Wi-Fi decides their order: an earlier run of the same firmware gave 129 / 146 / 156 ms (TLS) and
  340 / 298 / 304 ms (mTLS), and single handshakes reached 1.5–3.1 s.
- **The pipeline (ML-DSA-44, LoRaWAN 1.1 frames, 200 messages per block): 12 of 12 blocks.** The same BearSSL code
  seals / opens an uplink in 454 / 536 µs (Pico 700 / 852 µs), 611 / 694 µs with AES-256. The broker round trip is
  14–16 ms (Pico 6–7 ms): the Wi-Fi, not the board.
- **SNOVA round 3, all 9 sets: 15 of 15 blocks each, no crash or watchdog reset.** Connect (X25519MLKEM768, 50 each;
  ESP32 / Pico W):

  | Set | TLS | mTLS | Verify ×2 / sign | wolfSSL heap TLS / mTLS | Stack (mTLS) | Lowest free heap |
  |---|---|---|---|---|---|---|
  | I_K | 2,678 (2,250) | 4,135 (3,622) | 1,868 / 1,455 | 21.9 / 23.6 KB | 40.6 KB | 170 KB |
  | I_B | 2,342 (1,965) | 3,613 (3,133) | 1,545 / 1,254 | 22.2 / 24.3 KB | 36.5 KB | 174 KB |
  | I_S | 2,421 (1,846) | 3,650 (2,876) | 1,624 / 1,210 | 22.6 / 25.3 KB | 27.5 KB | 180 KB |
  | III_K | 5,116 (4,904) | 8,465 (8,032) | 4,281 / 3,340 | 22.5 / 25.4 KB | 60.5 KB | 148 KB |
  | III_B | 4,796 (4,758) | 7,987 (7,684) | 3,970 / 3,163 | 23.0 / 26.8 KB | 52.4 KB | 154 KB |
  | III_S | 4,760 (4,794) | 7,992 (7,697) | 3,921 / 3,233 | 23.6 / 28.5 KB | 50.6 KB | 152 KB |
  | V_K | 7,545 (7,479) | 12,897 (12,418) | 6,707 / 5,335 | 22.8 / 26.5 KB | 93.6 KB | 110 KB |
  | V_B | 6,898 (7,082) | 11,690 (11,645) | 6,102 / 4,774 | 23.4 / 28.3 KB | 80.4 KB | 123 KB |
  | V_S | 6,769 (7,078) | 11,541 (11,608) | 5,972 / 4,741 | 24.3 / 30.7 KB | 77.6 KB | 122 KB |

  (ms.) SNOVA runs at about the Pico's speed (I_K verify ×2 1.87 / 2.03 s, sign 1.45 / 1.36 s); the fixed ~720 ms of
  X25519 per handshake makes level I 14–31% slower, level III within 4%, and level V level or slightly faster. The
  stack peaks match the Pico's QEMU figures within 0.1 KB. V_K is the tightest fit: 93.6 of its 104 KB stack, 110 KB
  of heap left. The 72 pipeline blocks are all OK.
- **The other eight certificates** (connect, X25519MLKEM768, 50 each; ESP32 / Pico W):

  | Certificate | Blocks OK | TLS | mTLS | The device's signature | wolfSSL heap mTLS |
  |---|---|---|---|---|---|
  | RSA-2048 | 37 / 41 | 832 ms (269) | 2,192 ms (1,276) | 1,326 ms | 23.9 KB |
  | RSA-3072 | 37 / 41 | 914 ms (359) | 5,197 ms (3,626) | 4,219 ms | 24.8 KB |
  | ECDSA-P256 | 35 / 41 | 1,192 ms (397) | 1,336 ms (453) | 105 ms | 22.0 KB |
  | Ed25519 | 32 / 41 | 2,419 ms (351) | 3,147 ms (411) | 362 ms (28) | 23.1 KB |
  | ML-DSA-65 | 36 / 41 | 854 ms (332) | 1,031 ms (633) | 84 ms (211) | 50.7 KB |
  | ML-DSA-87 | 37 / 41 | 919 ms (413) | 1,139 ms (879) | 105 ms (345) | 63.4 KB |
  | Falcon-512 | 23 / 41 | 850 ms (229) | 1,298 ms (1,247) | 417 ms (1,001) | 75.9 KB |
  | Falcon-1024 | 18 / 41 | 913 ms (254) | out of memory (2,452) | – | fails at 113.6 KB (138.2) |

  wolfSSL's heap matches the Pico's within 0.1 KB on every certificate. Besides the two ML-KEM-512 hybrids:
  - **Falcon-1024 mTLS doesn't fit:** every mTLS block fails with `out of memory error` once wolfSSL holds 113.6 KB.
    About 200 KB is free, but in blocks of at most ~108 KB. TLS (the board only verifies) works: 914 ms, 27.5 KB.
  - **Falcon-512's mTLS sweep:** 11 of 13 blocks ended in `error state on socket`, mostly at the MQTT CONNECT after a
    complete handshake (the broker closed the connection), at -47 dBm and 185–200 KB free; the Pico's run had no such
    failures, and its connect mTLS block got 45 of 50. Not diagnosed (the Pi 4's broker log).
  - ECDSA-P256 lost two sweep blocks (mTLS X25519, x448_mlkem768) and Ed25519 five mTLS sweep blocks to the network.
  - Ed25519 is the slowest certificate here: verifying the two certificates takes 1.50 s per handshake (wolfSSL's
    small curve code, see below). ML-DSA and Falcon-512 sign 2.4–3.3× faster than on the Pico, so their mTLS
    handshakes come close to the Pico's despite the X25519.
- **The KEM exchange, as MQTT messages (50 each; ESP32 / Pico W):**

  | KEM | keygen + decapsulation on the board | The whole exchange |
  |---|---|---|
  | ML-KEM-512 / 768 / 1024 | 9.9 / 15.2 / 22.5 ms (15.6 / 24.1 / 35.9) | 31 / 34 / 44 ms (23 / 32 / 51) |
  | X25519 | 707 ms (849 small) | 721 ms (870 small, 126 normal) |
  | X25519MLKEM768 | 722 ms (874 small) | 747 ms (888 small, 153 normal) |
  | HQC-1 | 1,500 ms (2,048) | 1,582 ms (2,092) |

  The normal build reports `lib=wolfSSL_5.9.4_(small_X25519)` and times the same as the small build (353 ms per
  X25519 operation in both): wolfSSL's settings.h forces the small code on Xtensa (below). On that same code the
  ESP32 is 1.2× the Pico. HQC-1 fits: 64.8 KB of its 80 KB stack. The network round trip (19–22 ms, Pico 7–15 ms)
  takes back ML-KEM's gain on the whole exchange. The normal build lost two blocks to the network; the small build
  covers the same rows.
- **The deployment checks: all nine certificates.** The refusals (wrong broker IP: `peer ip address mismatch`;
  revoked: `CRL Cert revoked`; expired: `ASN date error`) are right on eight; loading the CRL takes 5 / 10 ms
  (Falcon-512 / 1024), 13 ms (ML-DSA-44), 21 / 35 ms (ML-DSA-65 / 87), 23 / 48 ms (RSA-2048 / 3072), 193 ms (ECDSA-P256)
  and 820 ms (Ed25519). The trust-anchor update (6.4 KB bundle fetched in 446 ms, verified in 15 ms, a tampered copy
  refused, 52 ms to flash, then accepted) and the frame counter across a reboot (328 before, 384 after: the reserved
  block, never a reused value; 8–9 ms per save) pass. Use the `-checked` rows for timing (TLS / mTLS, ESP32 / Pico):
  ML-DSA-44 894 / 964 ms (282 / 480), RSA-2048 847 / 2,229 ms (266 / 1,283), ECDSA-P256 1,186 / 1,326 ms (392 / 451),
  ML-DSA-65 1,056 / 1,267 ms (341 / 633), ML-DSA-87 1,044 / 2,264 ms (410 / 888), Falcon-512 847 / 1,276 ms
  (233 / 1,246). Not complete:
  - **Ed25519, twice:** its mTLS blocks and the revoked / expired refusals end in `error state on socket` or `no
    listener`, the broker closing the connection, at -51 dBm; only the wrong-name refusal is right. The same blocks
    failed in both runs, so it isn't the Wi-Fi; on the ESP32 an Ed25519 handshake takes 2.4 s and the CRL 0.82 s more.
    Not diagnosed (the broker's log for the DEPLOY_ED25519 listeners).
  - Falcon-1024 mTLS: `Buffer error`, then out of memory at 113.9 KB, as above.
  - The first mTLS block of ML-DSA-44, -65 and -87 hung (watchdog) after 7–12 connections, with TCP connects of
    0.4–1.3 s and MQTT steps of 0.8–1.8 s against ~10 ms normally; the `-checked` block right after was complete.
  - `NTP_SERVER=time.google.com` for the re-runs: `pool.ntp.org` gave no time for 8 minutes.

**Open questions.** Against the Pico W (200 MHz) most rows are 1.5–3× faster (clock 1.2×, plus the LX6's 32×32→64
multiply). Three groups are not, and comparing implementations of the same scheme on the same board narrows each one
down to a single library (the third is explained):

- **liboqs's SHAKE (SLH-DSA-SHAKE, and SNOVA, also liboqs) runs at the Pico's speed.** SLH-DSA-SHAKE-128f sign:
  ESP32 / Pico 15.7 / 15.0 s through liboqs (0.95×), 14.9 / 22.1 s through PQClean (1.48×), 9.6 / 16.5 s through
  wolfSSL (1.72×). On the Pico, liboqs is the fastest of the three. On the ESP32 it is no faster than PQClean. The
  Pico rows are plain liboqs, not the XKCP assembler build (`--keccak xkcp`), and the same liboqs SHA2 sets gain
  1.9× (SHA2-128f sign 2.10 / 4.02 s), so it's specific to liboqs's Keccak on the Xtensa build. Untested: where that
  code runs from (flash through the 32 KB cache), and the code generation flags `make_liboqs_lib.sh` builds with.
- **wolfSSL's SHA2 (SLH-DSA-SHA2) runs at the Pico's speed.** SHA2-128f sign: 5.31 / 5.40 s (1.02×); PQClean's
  1.65× and liboqs's 1.92× on the same sets. wolfSSL's ESP32 hardware SHA isn't the cause: settings.h only turns it on
  (`WOLFSSL_ESPIDF`) for PlatformIO, not for arduino-cli builds.
- **wolfSSL's Ed25519 is ~14× slower** (sign 361 / 26.7 ms), and in Stage 2 X25519 and X448 too (707 / 116 ms of
  key-exchange crypto per handshake; X448 + ML-KEM-768 1,588 / 427 ms). **Explained:** wolfSSL's own `settings.h`
  defines `CURVE25519_SMALL`, `ED25519_SMALL`, `CURVE448_SMALL` and `ED448_SMALL` for every `__xtensa__` build,
  whatever the user settings say, because Xtensa compilers "have been seen to compile C code into non-constant time
  assembly code" (it warns to contact wolfSSL for a fast constant-time version). So `WB_SMALL_25519` makes no
  difference on the ESP32: the KEM exchange's normal and small builds both report the small code and time the same.
  On the same small code the ESP32 is 1.2× the Pico (X25519 353 / 424 ms per operation). The Crypto library's
  Ed25519 (3.1× faster on the ESP32, sign 49 / 154 ms) shows the chip isn't the limit. It is a deliberate
  side-channel choice, not a fault: patching it out would give up constant time. It makes the customer's
  X25519MLKEM768 handshake 3× the Pico's (845 / 284 ms) while ML-KEM alone is faster. The P-curves are a smaller gap
  with a different cause: SP math in portable C here, Cortex-M assembly on the Pico (P-256 190 / 103 ms).

The `SLH-DSA … s` sets from PQClean follow the normal pattern: SHAKE 1.5× and SHA2-128s 1.6×. SHA2-192s and
SHA2-256s get up to 3.2× (verify). Those two use SHA-512, which is built on 64-bit operations that the Cortex-M0+
handles slowly.
