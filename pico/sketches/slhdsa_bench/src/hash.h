/* hash.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_sha2_128f) || defined(PICO_VARIANT_sha2_128s) || defined(PICO_VARIANT_sha2_192f) || defined(PICO_VARIANT_sha2_192s) || defined(PICO_VARIANT_sha2_256f) || defined(PICO_VARIANT_sha2_256s)
#include "hash__sha2.h"
#elif defined(PICO_VARIANT_shake_128f) || defined(PICO_VARIANT_shake_128s) || defined(PICO_VARIANT_shake_192f) || defined(PICO_VARIANT_shake_192s) || defined(PICO_VARIANT_shake_256f) || defined(PICO_VARIANT_shake_256s)
#include "hash__shake.h"
#endif
