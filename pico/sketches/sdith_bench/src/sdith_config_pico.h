/* sdith_config_pico.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_cat1)
#include "sdith_config_pico__cat1.h"
#elif defined(PICO_VARIANT_cat3)
#include "sdith_config_pico__cat3.h"
#endif
