// board_compat.h - the board calls the benches make, for arduino-pico (RP2040 / RP2350) and arduino-esp32.
//   On the Pico every call is the rp2040.* one the sketches used before, so Pico builds are unchanged.
//   run_benchmarks.py passes --libraries pico/libraries; a hand build needs the same flag.
#pragma once
#include <Arduino.h>

#if defined(ARDUINO_ARCH_RP2040)

#define BOARD_CHIP "RP2040"  // the banners said RP2040 on both RP families; the runner matches " on RP"
#define BOARD_FAMILY "RP"    // the big-stack sketches' banners: "on RP" for both RP families
static inline uint32_t board_hwrand32(void) { return rp2040.hwrand32(); }
static inline int board_free_stack(void) { return rp2040.getFreeStack(); }
static inline int board_free_heap(void) { return rp2040.getFreeHeap(); }
static inline void board_wdt_reset(void) { rp2040.wdt_reset(); }
static inline void board_reboot(void) { rp2040.reboot(); }
static inline uint32_t board_cpu_mhz(void) { return F_CPU / 1000000u; }
#define BOARD_LOOP_STACK(bytes)  // arduino-pico: loop() runs on the main stack (the sketches size it themselves)
// CPU cycles since boot: arduino-pico's 64-bit count (SysTick at the CPU clock, its overflow interrupt extends it)
static inline uint64_t board_cycles64(void) { return rp2040.getCycleCount64(); }
// what the chip is and what this firmware takes (the '#board' line). SRAM is the datasheet's: no register reports it.
// BOARD_CORE has no spaces (_ for a space): the #board line is k=v pairs split on spaces.
#if defined(__ARM_ARCH_6M__)
#define BOARD_MODEL "RP2040"
#define BOARD_CORE "Arm_Cortex-M0+"
#define BOARD_SRAM_KB 264
#else
#define BOARD_MODEL "RP2350"
#define BOARD_CORE "Arm_Cortex-M33"
#define BOARD_SRAM_KB 520
#endif
static inline int board_cores(void) { return 2; }
static inline uint32_t board_flash_bytes(void) { return PICO_FLASH_SIZE_BYTES; }
// the program image in flash: from the start of flash (XIP_BASE, 0x10000000) to the linker script's __flash_binary_end
#ifdef __cplusplus
extern "C" char __flash_binary_end;
#else
extern char __flash_binary_end;
#endif
static inline uint32_t board_sketch_bytes(void) { return (uint32_t)((uintptr_t)&__flash_binary_end - 0x10000000u); }
// the signature sketches' cycle counts: the ESP32 only (see there). On the Pico these leave the micros() timing as
// it was, and the cycles stay µs × MHz.
#define BOARD_HW_CYCLES 0
#define BOARD_STAMP(t) uint32_t t = micros()
#define BOARD_LAP(dst, a, b) ((void)0)
#define BOARD_CYC_ARRAY(name, n)
#define BOARD_CYC_PARAM(name)
#define BOARD_CYC_ARG(name)
#define BOARD_PRINT_CYC(label, x) ((void)0)

#elif defined(ARDUINO_ARCH_ESP32)

#include <esp_random.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#if CONFIG_IDF_TARGET_ESP32
#define BOARD_CHIP "ESP32"
#elif CONFIG_IDF_TARGET_ESP32S3
#define BOARD_CHIP "ESP32-S3"
#elif CONFIG_IDF_TARGET_ESP32C3
#define BOARD_CHIP "ESP32-C3"
#else
#define BOARD_CHIP "ESP32 (other)"
#endif
#define BOARD_FAMILY BOARD_CHIP
// esp_random(): the hardware RNG; true random while Wi-Fi / BT runs, else seeded by the bootloader's entropy
static inline uint32_t board_hwrand32(void) { return esp_random(); }
// the loop task's high-water mark: the LEAST free stack so far (rp2040.getFreeStack() is the free stack now)
static inline int board_free_stack(void) { return (int)uxTaskGetStackHighWaterMark(NULL); }
static inline int board_free_heap(void) { return (int)ESP.getFreeHeap(); }
static inline void board_wdt_reset(void) { esp_task_wdt_reset(); }
static inline void board_reboot(void) { ESP.restart(); }
static inline uint32_t board_cpu_mhz(void) { return getCpuFrequencyMhz(); }
// loop() is a FreeRTOS task with an 8 KB stack by default; the PQC benches need far more. At file scope.
#define BOARD_LOOP_STACK(bytes) SET_LOOP_TASK_STACK_SIZE(bytes)
// CPU cycles since boot, from the core's 32-bit cycle counter (CCOUNT on Xtensa), widened to 64 bits here. It wraps
// every 2^32 cycles (17.9 s at 240 MHz): callers read it more often than that. Per core: the loop task stays on one.
static inline uint64_t board_cycles64(void) {
  static uint32_t last;
  static uint64_t high;
  uint32_t now = ESP.getCycleCount();
  if (now < last) high += 1ull << 32;
  last = now;
  return high | now;
}
// what the chip is and what this firmware takes (the '#board' line). SRAM is the datasheet's: no register reports it.
// BOARD_CORE has no spaces (_ for a space): the #board line is k=v pairs split on spaces.
#if CONFIG_IDF_TARGET_ESP32
#define BOARD_CORE "Xtensa_LX6"
#define BOARD_SRAM_KB 520
#elif CONFIG_IDF_TARGET_ESP32S3
#define BOARD_CORE "Xtensa_LX7"
#define BOARD_SRAM_KB 512
#elif CONFIG_IDF_TARGET_ESP32C3
#define BOARD_CORE "RISC-V_RV32IMC"
#define BOARD_SRAM_KB 400
#else
#define BOARD_CORE "?"
#define BOARD_SRAM_KB 0
#endif
#define BOARD_MODEL ESP.getChipModel()  // e.g. ESP32-D0WD-V3: the eFuse's package and revision
static inline int board_cores(void) { return ESP.getChipCores(); }
static inline uint32_t board_flash_bytes(void) { return ESP.getFlashChipSize(); }
static inline uint32_t board_sketch_bytes(void) { return ESP.getSketchSize(); }  // the app image in flash

// ---- the signature sketches' cycle counts (ESP32 only) ----
// A mark is the 64-bit µs timer (esp_timer, what micros() returns) and the core's CCOUNT, read together. The µs
// value stays the sketches' timing; the cycles between two marks come from CCOUNT. CCOUNT is 32-bit and wraps every
// 17.9 s at 240 MHz, and one call (SLH-DSA "s" signing, RSA keygen) can last minutes with nothing reading it in
// between, so the µs timer counts the whole wraps: it is within ~1 µs, far inside the ±8.9 s that would be needed to
// get the count wrong. Per core: the loop task (and the big-stack runs, on the same task) stays on core 1.
#define BOARD_HW_CYCLES 1
#define BOARD_CYC_SRC "CCOUNT"
typedef struct { int64_t us; uint32_t cc; } board_mark_t;
static inline board_mark_t board_mark(void) {
  board_mark_t m;
  m.us = esp_timer_get_time();
  m.cc = ESP.getCycleCount();
  return m;
}
static inline uint64_t board_lap_cycles(board_mark_t a, board_mark_t b) {
  uint32_t lo = b.cc - a.cc;                                     // exact, modulo 2^32
  uint64_t est = (uint64_t)(b.us - a.us) * board_cpu_mhz();      // the µs timer's count, to ~1 µs
  uint64_t wraps = est > lo ? (est - lo + (1ull << 31)) >> 32 : 0; // nearest whole number of wraps
  return (wraps << 32) + lo;
}
// "  mean_cyc=… median_cyc=… min_cyc=… max_cyc=… cyc_src=CCOUNT" on a summary line: the runner keeps these when
// cyc_src= is there (older logs: µs × MHz). The median is the sketches' own: the lower average of the middle two.
static inline void board_print_cyc_stats(const uint64_t *c, int n) {
  if (!c || n <= 0) return;
  uint64_t *s = (uint64_t *)malloc(sizeof(uint64_t) * n);
  if (!s) return;
  uint64_t sum = 0;
  for (int i = 0; i < n; i++) { s[i] = c[i]; sum += c[i]; }
  for (int i = 1; i < n; i++) { uint64_t k = s[i]; int j = i - 1; while (j >= 0 && s[j] > k) { s[j + 1] = s[j]; j--; } s[j + 1] = k; }
  uint64_t med = (n & 1) ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) >> 1;
  Serial.printf("  mean_cyc=%llu  median_cyc=%llu  min_cyc=%llu  max_cyc=%llu  cyc_src=" BOARD_CYC_SRC,
                (unsigned long long)(sum / n), (unsigned long long)med, (unsigned long long)s[0],
                (unsigned long long)s[n - 1]);
  free(s);
}
// BOARD_STAMP(t) declares uint32_t t (µs, as micros()) and its mark t_m; BOARD_LAP(dst, a, b) = the cycles a → b
#define BOARD_STAMP(t) board_mark_t t##_m = board_mark(); uint32_t t = (uint32_t)t##_m.us
#define BOARD_LAP(dst, a, b) ((dst) = board_lap_cycles(a##_m, b##_m))
#define BOARD_CYC_ARRAY(name, n) static uint64_t name[n];
#define BOARD_CYC_PARAM(name) , uint64_t *name
#define BOARD_CYC_ARG(name) , name
#define BOARD_PRINT_CYC(label, x) Serial.printf(" " label "=%llu", (unsigned long long)(x))

#else
#error "board_compat.h: arduino-pico (RP2040 / RP2350) or arduino-esp32 only"
#endif
