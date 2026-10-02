#ifdef SUPERCOP
#  include "crypto_sign.h"

#  include <string.h>
#  include "randombytes.h"
#  include "qruov.h"
#  include "api.h"
#else
#  include <string.h>
#  include "api.h"
#  include "rng.h"
#endif

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  QRUOV_SEED seed_sk ; randombytes(seed_sk, QRUOV_SEED_LEN) ;
  QRUOV_SEED seed_pk ; randombytes(seed_pk, QRUOV_SEED_LEN) ;
  static QRUOV_P3 P3 ; // to avoid huge array in stack,
                       // (but problematic in mult-thread environment)

  QRUOV_KeyGen (seed_sk, seed_pk, P3) ;

  size_t sk_pool_bits = 0 ;
  store_QRUOV_SEED(seed_sk, sk, &sk_pool_bits) ;
  store_QRUOV_SEED(seed_pk, sk, &sk_pool_bits) ;

  size_t pk_pool_bits = 0 ;
  store_QRUOV_SEED(seed_pk, pk, &pk_pool_bits) ;
  store_QRUOV_P3  (P3,      pk, &pk_pool_bits) ;

  return 0 ;
}

int
crypto_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk)
{

  size_t sk_pool_bits = 0 ;
  QRUOV_SEED seed_sk      ; restore_QRUOV_SEED(sk, &sk_pool_bits, seed_sk) ;
  QRUOV_SEED seed_pk      ; restore_QRUOV_SEED(sk, &sk_pool_bits, seed_pk) ;

  QRUOV_SEED seed_y       ; randombytes(seed_y  , QRUOV_SEED_LEN) ;
  QRUOV_SEED seed_r       ; randombytes(seed_r  , QRUOV_SEED_LEN) ;
  QRUOV_SEED seed_sol     ; randombytes(seed_sol, QRUOV_SEED_LEN) ;

  QRUOV_SIGNATURE sig     ;
  QRUOV_Sign(seed_sk, seed_pk, seed_y, seed_r, seed_sol, m, mlen, sig) ;

  size_t sig_pool_bits = 0 ;
  store_QRUOV_SIGNATURE(sig, sm, &sig_pool_bits) ;

  memcpy(sm+CRYPTO_BYTES,m,mlen) ;
  *smlen = CRYPTO_BYTES+mlen ;

  return 0 ;
}

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk){

  size_t pk_pool_bits = 0 ;
  QRUOV_SEED seed_pk      ; restore_QRUOV_SEED(pk, &pk_pool_bits, seed_pk) ;
  static QRUOV_P3 P3      ; // to avoid huge array in stack
                            // (but problematic in mult-thread environment)

  restore_QRUOV_P3(pk, &pk_pool_bits, P3) ;

  size_t sig_pool_bits = 0 ;
  QRUOV_SIGNATURE sig ; restore_QRUOV_SIGNATURE(sm, &sig_pool_bits, sig) ;

  if(QRUOV_Verify(seed_pk, P3, sm+CRYPTO_BYTES, smlen-CRYPTO_BYTES, sig)){
    *mlen = smlen - CRYPTO_BYTES ;
    memcpy(m, sm+CRYPTO_BYTES, *mlen) ;
  }else{
    return 1 ;
  }

  return 0 ;
}
