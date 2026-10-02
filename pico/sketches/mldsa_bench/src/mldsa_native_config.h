/* mldsa_native_config.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_44)
#include "mldsa_native_config__44.h"
#elif defined(PICO_VARIANT_65)
#include "mldsa_native_config__65.h"
#elif defined(PICO_VARIANT_87)
#include "mldsa_native_config__87.h"
#endif
