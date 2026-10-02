// slhdsa_bench.ino - one sketch for every parameter set of this family (was 12 folders:
//   slhdsa_sha2_128f_bench, slhdsa_sha2_128s_bench, slhdsa_sha2_192f_bench, slhdsa_sha2_192s_bench, slhdsa_sha2_256f_bench, slhdsa_sha2_256s_bench, slhdsa_shake_128f_bench, slhdsa_shake_128s_bench, slhdsa_shake_192f_bench, slhdsa_shake_192s_bench, slhdsa_shake_256f_bench, slhdsa_shake_256s_bench).
//   run_benchmarks.py picks one with -DPICO_VARIANT_<v>. Each variant's original sketch is kept
//   verbatim in src/ino__<v>.h; files that differ per variant are src/<name>__<v>.*, selected the
//   same way. Files shared by all variants are stored once.
#include <Arduino.h>
#if defined(PICO_VARIANT_sha2_128f)
#include "src/ino__sha2_128f.h"
#elif defined(PICO_VARIANT_sha2_128s)
#include "src/ino__sha2_128s.h"
#elif defined(PICO_VARIANT_sha2_192f)
#include "src/ino__sha2_192f.h"
#elif defined(PICO_VARIANT_sha2_192s)
#include "src/ino__sha2_192s.h"
#elif defined(PICO_VARIANT_sha2_256f)
#include "src/ino__sha2_256f.h"
#elif defined(PICO_VARIANT_sha2_256s)
#include "src/ino__sha2_256s.h"
#elif defined(PICO_VARIANT_shake_128f)
#include "src/ino__shake_128f.h"
#elif defined(PICO_VARIANT_shake_128s)
#include "src/ino__shake_128s.h"
#elif defined(PICO_VARIANT_shake_192f)
#include "src/ino__shake_192f.h"
#elif defined(PICO_VARIANT_shake_192s)
#include "src/ino__shake_192s.h"
#elif defined(PICO_VARIANT_shake_256f)
#include "src/ino__shake_256f.h"
#elif defined(PICO_VARIANT_shake_256s)
#include "src/ino__shake_256s.h"
#else
#error "build with -DPICO_VARIANT_<v>, v = sha2_128f | sha2_128s | sha2_192f | sha2_192s | sha2_256f | sha2_256s | shake_128f | shake_128s | shake_192f | shake_192s | shake_256f | shake_256s"
#endif
