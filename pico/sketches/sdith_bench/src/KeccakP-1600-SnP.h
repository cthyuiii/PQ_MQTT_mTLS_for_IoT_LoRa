/* KeccakP-1600-SnP.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_cat1)
#include "KeccakP-1600-SnP__cat1.h"
#elif defined(PICO_VARIANT_cat3)
#include "KeccakP-1600-SnP__cat3.h"
#endif
