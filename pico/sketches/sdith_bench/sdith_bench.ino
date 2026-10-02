// sdith_bench.ino - one sketch for every parameter set of this family (was 2 folders:
//   sdith_cat1_bench, sdith_cat3_bench).
//   run_benchmarks.py picks one with -DPICO_VARIANT_<v>. Each variant's original sketch is kept
//   verbatim in src/ino__<v>.h; files that differ per variant are src/<name>__<v>.*, selected the
//   same way. Files shared by all variants are stored once.
#include <Arduino.h>
#if defined(PICO_VARIANT_cat1)
#include "src/ino__cat1.h"
#elif defined(PICO_VARIANT_cat3)
#include "src/ino__cat3.h"
#else
#error "build with -DPICO_VARIANT_<v>, v = cat1 | cat3"
#endif
