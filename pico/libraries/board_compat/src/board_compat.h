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

#elif defined(ARDUINO_ARCH_ESP32)

#include <esp_random.h>
#include <esp_task_wdt.h>
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

#else
#error "board_compat.h: arduino-pico (RP2040 / RP2350) or arduino-esp32 only"
#endif
