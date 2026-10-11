// mldsa_bench.ino - one sketch for every parameter set of this family (was 3 folders:
//   mldsa44_bench, mldsa65_bench, mldsa87_bench).
//   run_benchmarks.py picks one with -DPICO_VARIANT_<v>. Each variant's original sketch is kept
//   verbatim in src/ino__<v>.h; files that differ per variant are src/<name>__<v>.*, selected the
//   same way. Files shared by all variants are stored once.
#include <Arduino.h>
#include <board_compat.h>
// ESP32 only: loop() is a FreeRTOS task, 8 KB by default. Peaks there: 44 = 45 KB, 65 = 69 KB of 96 KB
#if defined(PICO_VARIANT_87)
BOARD_LOOP_STACK(106 * 1024);  // the largest free block on a WROOM-32 is ~108 KB: more never starts
#else
BOARD_LOOP_STACK(96 * 1024);
#endif
#if defined(PICO_VARIANT_44)
#include "src/ino__44.h"
#elif defined(PICO_VARIANT_65)
#include "src/ino__65.h"
#elif defined(PICO_VARIANT_87)
#include "src/ino__87.h"
#else
#error "build with -DPICO_VARIANT_<v>, v = 44 | 65 | 87"
#endif
