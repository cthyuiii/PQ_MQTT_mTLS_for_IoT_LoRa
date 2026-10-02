/* shake_offsets.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_shake_128f) || defined(PICO_VARIANT_shake_128s) || defined(PICO_VARIANT_shake_192f) || defined(PICO_VARIANT_shake_192s) || defined(PICO_VARIANT_shake_256f) || defined(PICO_VARIANT_shake_256s)
#include "shake_offsets__shake.h"
#endif
