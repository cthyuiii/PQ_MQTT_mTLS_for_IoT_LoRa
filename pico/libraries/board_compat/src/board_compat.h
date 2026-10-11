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

#else
#error "board_compat.h: arduino-pico (RP2040 / RP2350) or arduino-esp32 only"
#endif
