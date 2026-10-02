/* api.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_128f)
#include "api__128f.h"
#elif defined(PICO_VARIANT_192f)
#include "api__192f.h"
#elif defined(PICO_VARIANT_256f)
#include "api__256f.h"
#elif defined(PICO_VARIANT_em_128f)
#include "api__em_128f.h"
#endif
