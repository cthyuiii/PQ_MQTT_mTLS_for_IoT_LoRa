#pragma once
#  include "qruov_config.h"

/*
  QRUOV_security_strength_category // 1/3/5
  QRUOV_q                          // 7/31/127
  QRUOV_v                          // v
  QRUOV_m                          // m
  QRUOV_L                          // L    : f = x^L - fc * x^fe - fc0
  QRUOV_fc                         // fc
  QRUOV_fe                         // fe
  QRUOV_fc0                        // fc0
  QRUOV_PLATFORM                   // ref/portable/avx2/avx512
*/

#ifndef QRUOV_security_strength_category
#  error "QRUOV_security_strength_category is not defined."
#endif

#ifndef QRUOV_q
#  error "QRUOV_q is not defined."
#endif

#ifndef QRUOV_v
#  error "QRUOV_v is not defined."
#endif

#ifndef QRUOV_m
#  error "QRUOV_m is not defined."
#endif

#ifndef QRUOV_L
#  error "QRUOV_L is not defined."
#endif

#ifndef QRUOV_fc
#  error "QRUOV_fc is not defined."
#endif

#ifndef QRUOV_fe
#  error "QRUOV_fe is not defined."
#endif

#ifndef QRUOV_fc0
#  define QRUOV_fc0 1
#endif

#ifndef QRUOV_PLATFORM
#  error "QRUOV_PLATFORM is not defined."
#endif

// QRUOV_q == ((1 << QRUOV_ceil_log_2_q) - 1)

#if   (QRUOV_q == 7)
#  define QRUOV_ceil_log_2_q 3
#elif (QRUOV_q == 31)
#  define QRUOV_ceil_log_2_q 5
#elif (QRUOV_q == 127)
#  define QRUOV_ceil_log_2_q 7
#else
#  error "Unsupported: QRUOV_q == " # QRUOV_q
#endif

#if   (QRUOV_security_strength_category == 1)
#  define QRUOV_SEED_LEN 16                   // 16 Byte == 128 bit
#elif (QRUOV_security_strength_category == 3)
#  define QRUOV_SEED_LEN 24                   // 24 Byte == 192 bit
#elif (QRUOV_security_strength_category == 5)
#  define QRUOV_SEED_LEN 32                   // 32 Byte == 256 bit
#else
#  error "Unsupported: QRUOV_security_strength_category == " # QRUOV_security_strength_category
#endif

#define QRUOV_n             ((QRUOV_v)+(QRUOV_m))
#define QRUOV_N             ((QRUOV_n)/(QRUOV_L))
#define QRUOV_V             ((QRUOV_v)/(QRUOV_L))
#define QRUOV_M             ((QRUOV_m)/(QRUOV_L))

#define QRUOV_perm(i)       ((i<=(QRUOV_fe-1))?((QRUOV_fe-1)-i):(QRUOV_L+(QRUOV_fe-1)-i))

#define QRUOV_STR_INDIR(x)  #x
#define QRUOV_STR(x)        QRUOV_STR_INDIR(x)

#define QRUOV_ALGNAME                                 \
  "qruov" QRUOV_STR(QRUOV_security_strength_category) \
  "q"     QRUOV_STR(QRUOV_q)                          \
  "L"     QRUOV_STR(QRUOV_L)                          \
  "v"     QRUOV_STR(QRUOV_v)                          \
  "m"     QRUOV_STR(QRUOV_m)                          \
          QRUOV_STR(QRUOV_PLATFORM)

#ifndef QRUOV_PARAM_DESCRIPTION
#  define QRUOV_PARAM_DESCRIPTION                           \
  "QR-UOV ("                                                \
    "cat=" QRUOV_STR(QRUOV_security_strength_category) ", " \
    "q="   QRUOV_STR(QRUOV_q)                          ", " \
    "L="   QRUOV_STR(QRUOV_L)                          ", " \
    "v="   QRUOV_STR(QRUOV_v)                          ", " \
    "m="   QRUOV_STR(QRUOV_m)                               \
  ")"
#endif

#define TYPEDEF_STRUCT(TYPE_NAME, BODY)             \
typedef struct TYPE_NAME ## _t {                    \
  BODY                                              \
} TYPE_NAME ## _s, * TYPE_NAME ## _p, TYPE_NAME [1]

#define ERROR_ABORT(MESSAGE) { \
  fprintf(stderr, "runtime error: %s in file: %s, line: %d.\n",MESSAGE,__FILE__,__LINE__); \
  abort(); \
}

//=============================================================
// qruov_misc.h (for random_sampling.c)
//=============================================================

#define BITS2BYTES(BITS)           (((BITS)>>3)+(((BITS)&7)?1:0))

#define QRUOV_SALT_LEN QRUOV_SEED_LEN

#define QRUOV_MU_LEN   64 // 64 byte == 512 bit, message representative

#define ALIGN_8BIT   __attribute((__aligned__( 1))) ; //   8 bit
#define ALIGN_16BIT  __attribute((__aligned__( 2))) ; //  16 bit
#define ALIGN_32BIT  __attribute((__aligned__( 4))) ; //  32 bit
#define ALIGN_64BIT  __attribute((__aligned__( 8))) ; //  64 bit
#define ALIGN_128BIT __attribute((__aligned__(16))) ; // 128 bit
#define ALIGN_256BIT __attribute((__aligned__(32))) ; // 256 bit
#define ALIGN_512BIT __attribute((__aligned__(64))) ; // 512 bit
