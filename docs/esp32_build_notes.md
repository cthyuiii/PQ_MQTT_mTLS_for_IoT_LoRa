# PQC Signatures on the ESP32 (ESP32-WROOM-32UE) — Build Notes

The ESP32 port of the Pico's Stage 1 sketches (11 Oct 2026). How each sketch was brought up on the RP2040, and what failed there, is in [pico_build_notes.md](pico_build_notes.md).

The Stage 1 sketches also build for a classic ESP32 (Xtensa LX6 dual core @ 240 MHz, ~320 KB DRAM, no PSRAM;
`arduino-esp32` 3.3.12, FQBN `esp32:esp32:esp32`). Run them with
`python pico/run_benchmarks.py --board esp32 --tag esp32` (results in `pico/logs_esp32/`). The Pico builds are meant
to be unchanged: every board call goes through `pico/libraries/board_compat/src/board_compat.h`, which maps to the same
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
heap), SDitH (335 KB).

**Open questions.** Against the Pico W (200 MHz) most rows are 1.5–3× faster (clock 1.2×, plus the LX6's 32×32→64
multiply). Three groups are not, and comparing implementations of the same scheme on the same board narrows each one
down to a single library:

- **liboqs's SHAKE (SLH-DSA-SHAKE, and SNOVA, also liboqs) runs at the Pico's speed.** SLH-DSA-SHAKE-128f sign:
  ESP32 / Pico 15.7 / 15.0 s through liboqs (0.95×), 14.9 / 22.1 s through PQClean (1.48×), 9.6 / 16.5 s through
  wolfSSL (1.72×). On the Pico, liboqs is the fastest of the three. On the ESP32 it is no faster than PQClean. The
  Pico rows are plain liboqs, not the XKCP assembler build (`--keccak xkcp`), and the same liboqs SHA2 sets gain
  1.9× (SHA2-128f sign 2.10 / 4.02 s), so it's specific to liboqs's Keccak on the Xtensa build. Untested: where that
  code runs from (flash through the 32 KB cache), and the code generation flags `make_liboqs_lib.sh` builds with.
- **wolfSSL's SHA2 (SLH-DSA-SHA2) runs at the Pico's speed.** SHA2-128f sign: 5.31 / 5.40 s (1.02×); PQClean's
  1.65× and liboqs's 1.92× on the same sets. wolfSSL's ESP32 hardware SHA isn't the cause: settings.h only turns it on
  (`WOLFSSL_ESPIDF`) for PlatformIO, not for arduino-cli builds.
- **wolfSSL's Ed25519 is ~14× slower** (sign 361 / 26.7 ms). It's wolfSSL's code, not the curve: the Crypto library's
  Ed25519 is 3.1× faster on the ESP32 (sign 49 / 154 ms). `WB_SMALL_25519` (wolfSSL's small, slow curve code) is off
  in both builds.

The `SLH-DSA … s` sets from PQClean follow the normal pattern: SHAKE 1.5× and SHA2-128s 1.6×. SHA2-192s and
SHA2-256s get up to 3.2× (verify). Those two use SHA-512, which is built on 64-bit operations that the Cortex-M0+
handles slowly.
