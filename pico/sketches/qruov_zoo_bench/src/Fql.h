#pragma once
#include "qruov_misc.h"
#include "mgf.h"

/* =====================================================================
   F_q
   ===================================================================== */

typedef uint8_t Fq ;

// ============================================================================
// Fq add/sub ...
// ============================================================================

inline static Fq Fq_add(Fq X, Fq Y){ return (Fq)(((int) X + (int) Y) % QRUOV_q) ; }
inline static Fq Fq_sub(Fq X, Fq Y){ return (Fq)(((int) X - (int) Y + QRUOV_q) % QRUOV_q) ; }
inline static Fq Fq_mul(Fq X, Fq Y){ return (Fq)(((int) X * (int) Y) % QRUOV_q) ; }
inline static Fq Fq_inv(Fq X){ extern Fq Fq_inv_table[QRUOV_q] ; return Fq_inv_table[X] ; }

// ============================================================================
// F_q^L = F_q[X]/(f(X))
// ============================================================================

typedef struct Fql_t {
  Fq c[QRUOV_L] ;
} Fql ;

extern Fql Fql_zero ;

// ============================================================================
// F_q^L House keeping
// ============================================================================

inline static Fq  Fql2Fq(Fql Z, int i){ return Z.c[i] ; }
inline static Fql Fq2Fql(uint8_t c[QRUOV_L]){ return *(Fql*)c ; }

// ============================================================================
// Fq^L add/sub
// ============================================================================

inline static Fql Fql_add(Fql X, Fql Y){
  for(int i=0; i<QRUOV_L; i++) X.c[i] = Fq_add(X.c[i], Y.c[i]);
  return X ;
}

inline static Fql Fql_sub(Fql X, Fql Y){
  for(int i=0; i<QRUOV_L; i++) X.c[i] = Fq_sub(X.c[i], Y.c[i]);
  return X ;
}

// ============================================================================
// Fq^L mul
// ============================================================================

inline static Fql Fql_mul(Fql X, Fql Y){
  int T[2*QRUOV_L-1] ;
  memset(T, 0, sizeof(T)) ;

  for(size_t i=0; i<QRUOV_L; i++){
    for(size_t j=0; j<QRUOV_L; j++){
      T[i+j] += (int) X.c[i] * (int) Y.c[j] ;
    }
  }

  for(size_t i = 2*QRUOV_L-2; i >= QRUOV_L; i--){
      T[i-QRUOV_L]          += QRUOV_fc0 * T[i] ;
      T[i-QRUOV_L+QRUOV_fe] += QRUOV_fc  * T[i] ;
  }

  Fql Z ;
  for(size_t i=0; i<QRUOV_L; i++) Z.c[i] = (Fq)(T[i] % QRUOV_q) ;
  return Z ;
}

/* =====================================================================
   memory I/O
   ===================================================================== */

inline static void store_bits(
  int             x,               // \in {0,...,255}
  const int       num_bits,        // \in {0,...,8}
  uint8_t       * pool,            //
  size_t        * pool_bits
){
  int    shift = (int)(*pool_bits &  7) ;
  size_t index = (*pool_bits >> 3) ;
  int    mask  = (1<<num_bits) - 1 ;

  x &= mask ;
  x <<= shift ;
  uint8_t x0 = (x & 0xFF) ;
  if(shift == 0){
    pool[index] = x0 ;
  }else{
    pool[index] |= x0 ;
  }
  if(shift + num_bits > 8){
    uint8_t x1 = (x >> 8) ;
    pool[index+1] = x1 ;
  }

  *pool_bits += (size_t) num_bits ;
}

inline static int restore_bits(     // \in {0,...,255}
  const uint8_t * pool,
  size_t        * pool_bits,
  const int       num_bits          // \in {0,...,8}
){
  int    shift = (int)(*pool_bits &  7) ;
  size_t index = (*pool_bits >> 3) ;
  int    mask  = (1<<num_bits) - 1 ;

  int x        = ((int) pool[index]) 
               | (((shift + num_bits > 8) ? (int)pool[index+1] : 0) << 8) ;
  x >>= shift ;
  x &= mask ; 
  *pool_bits += (size_t) num_bits ;
  return x ;
}

inline static void store_Fq(
  int             x,               // \in Fq
  uint8_t       * pool,
  size_t        * pool_bits
){
  store_bits(x, QRUOV_ceil_log_2_q, pool, pool_bits) ;
}

inline static Fq restore_Fq(
  const uint8_t * pool,
  size_t        * pool_bits
){
  return (Fq) restore_bits(pool, pool_bits, QRUOV_ceil_log_2_q) ;
}

inline static void store_Fq_vector(
  const Fq  * X,
  const int   n,
  uint8_t   * pool,
  size_t    * pool_bits
){
  for(size_t i=0; i<n; i++) store_Fq(X[i], pool, pool_bits) ;
}

inline static void restore_Fq_vector(
  const uint8_t * pool,
  size_t        * pool_bits,
  Fq            * Z,
  const size_t    n
){
  for(size_t i=0; i<n; i++) Z[i] = restore_Fq(pool, pool_bits) ;
}

inline static void store_Fql(
  const Fql       X,
  uint8_t       * pool,            // bit pool
  size_t        * pool_bits        // current bit index
){
  store_Fq_vector(X.c, QRUOV_L, pool, pool_bits) ;
}

inline static Fql restore_Fql(
  const uint8_t * pool,            // bit pool
  size_t        * pool_bits        // current bit index
){
  Fql Z ;
  restore_Fq_vector(pool, pool_bits, Z.c, QRUOV_L) ;
  return Z ;
}

inline static void store_Fql_vector(
  const Fql    * X,
  const size_t   n,
  uint8_t      * pool,
  size_t       * pool_bits
){
  for(size_t i=0; i<n; i++) store_Fql(X[i], pool, pool_bits) ;
}

inline static void restore_Fql_vector(
  const uint8_t * pool,
  size_t        * pool_bits,
  Fql           * Z,
  const size_t    n
){
  for(size_t i=0; i<n; i++) Z[i] = restore_Fql(pool, pool_bits) ;
}
