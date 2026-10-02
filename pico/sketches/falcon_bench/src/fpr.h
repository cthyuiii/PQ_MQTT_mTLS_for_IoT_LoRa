/* fpr.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_512)
#include "fpr__512.h"
#elif defined(PICO_VARIANT_1024)
#include "fpr__1024.h"
#endif
