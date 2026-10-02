#pragma once
#include "qruov_misc.h"

static inline void sample_random_and_q (
  const unsigned int length,
  uint8_t * dst
){
  for(int i=0; i<length; i++){ dst[i] &= QRUOV_q ; }
}

static inline void sample_random_rejection_with_aux(
  const unsigned int length,
  const uint8_t *    aux,
        uint8_t *    dst
){
  while(*aux==QRUOV_q)aux++ ;
  for(int i=0; i<length; i++){
    if(*dst==QRUOV_q){
      *dst = *aux++ ;
      while(*aux==QRUOV_q)aux++ ;
    }
    *dst++ ;
  }
}

#if 0

static inline void sample_random_mod_q (
  const unsigned int length,
  uint8_t * dst
){
  for(int i=0; i<length; i++){ dst[i] %= QRUOV_q ; }
}

static inline void sample_random_and_mod_q (
  const unsigned int length,
  uint8_t * dst
){
  for(int i=0; i<length; i++){ if((dst[i] &= QRUOV_q)==QRUOV_q) dst[i] = 0 ; }
}


static inline void sample_random_rejection (
  const unsigned int length,
  const uint8_t *    src,     // #{ i | src[i] != QRUOV_q } >= length
        uint8_t *    dst
){
  while(*src==QRUOV_q)src++ ;
  for(int i=0; i<length; i++){
    *dst++ = *src++ ;
    while(*src==QRUOV_q)src++ ;
  }
}

static inline void sample_random_rejection_interleave(
  const unsigned int length,
        uint8_t *    dst
){
  const uint8_t *    src = dst + length ;
  while(*src==QRUOV_q)src++ ;

  for(int i=0; i<length; i++){
    if(*dst==QRUOV_q){
      *dst = *src++ ;
      while(*src==QRUOV_q)src++ ;
    }
    *dst++ ;
  }
}

#endif
