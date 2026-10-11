// hawk_bench.ino - one sketch for every parameter set of this family (was 2 folders:
//   hawk512_bench, hawk1024_bench).
//   run_benchmarks.py picks one with -DPICO_VARIANT_<v>. Each variant's original sketch is kept
//   verbatim in src/ino__<v>.h; files that differ per variant are src/<name>__<v>.*, selected the
//   same way. Files shared by all variants are stored once.
#include <Arduino.h>
#include <board_compat.h>
// ESP32 only: loop() is a FreeRTOS task, 8 KB by default. Pico working set: 512 = 40 KB, 1024 = 60 KB
#if defined(PICO_VARIANT_1024)
BOARD_LOOP_STACK(80 * 1024);
#else
BOARD_LOOP_STACK(64 * 1024);
#endif
#if defined(PICO_VARIANT_512)
#include "src/ino__512.h"
#elif defined(PICO_VARIANT_1024)
#include "src/ino__1024.h"
#else
#error "build with -DPICO_VARIANT_<v>, v = 512 | 1024"
#endif
