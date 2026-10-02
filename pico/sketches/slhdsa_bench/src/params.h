/* params.h: differs between parameter sets; the build picks one with -DPICO_VARIANT_<v> */
#if defined(PICO_VARIANT_sha2_128f)
#include "params__sha2_128f.h"
#elif defined(PICO_VARIANT_sha2_128s)
#include "params__sha2_128s.h"
#elif defined(PICO_VARIANT_sha2_192f)
#include "params__sha2_192f.h"
#elif defined(PICO_VARIANT_sha2_192s)
#include "params__sha2_192s.h"
#elif defined(PICO_VARIANT_sha2_256f)
#include "params__sha2_256f.h"
#elif defined(PICO_VARIANT_sha2_256s)
#include "params__sha2_256s.h"
#elif defined(PICO_VARIANT_shake_128f)
#include "params__shake_128f.h"
#elif defined(PICO_VARIANT_shake_128s)
#include "params__shake_128s.h"
#elif defined(PICO_VARIANT_shake_192f)
#include "params__shake_192f.h"
#elif defined(PICO_VARIANT_shake_192s)
#include "params__shake_192s.h"
#elif defined(PICO_VARIANT_shake_256f)
#include "params__shake_256f.h"
#elif defined(PICO_VARIANT_shake_256s)
#include "params__shake_256s.h"
#endif
