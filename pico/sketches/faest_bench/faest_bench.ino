// faest_bench.ino - one sketch for every parameter set of this family (was 4 folders:
//   faest_128f_bench, faest_192f_bench, faest_256f_bench, faest_em_128f_bench).
//   run_benchmarks.py picks one with -DPICO_VARIANT_<v>. Each variant's original sketch is kept
//   verbatim in src/ino__<v>.h; files that differ per variant are src/<name>__<v>.*, selected the
//   same way. Files shared by all variants are stored once.
#include <Arduino.h>
#include <board_compat.h>
BOARD_LOOP_STACK(32 * 1024);  // ESP32 only: loop() is a FreeRTOS task, 8 KB by default
#if defined(PICO_VARIANT_128f)
#include "src/ino__128f.h"
#elif defined(PICO_VARIANT_192f)
#include "src/ino__192f.h"
#elif defined(PICO_VARIANT_256f)
#include "src/ino__256f.h"
#elif defined(PICO_VARIANT_em_128f)
#include "src/ino__em_128f.h"
#else
#error "build with -DPICO_VARIANT_<v>, v = 128f | 192f | 256f | em_128f"
#endif
