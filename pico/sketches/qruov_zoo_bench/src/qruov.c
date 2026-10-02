#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <math.h>
#include "qruov.h"
#include "post_sample.h"

/* ---------------------------------------------------------
   misc
   --------------------------------------------------------- */

#if __BIG_ENDIAN__

static inline uint64_t load64(const uint8_t src [8]) {
  return * (uint64_t *) src ;
}
static inline void save64(const uint64_t s, uint8_t dst[8]) {
  uint64_t * d = (uint64_t *) dst ;
  *d = s ;
}
static inline uint32_t load32(const uint8_t src [4]) {
  return * (uint32_t *) src ;
}
static inline void save32(const uint32_t s, uint8_t dst[4]) {
  uint32_t * d = (uint32_t *) dst ;
  *d = s ;
}

static inline uint16_t load16(const uint8_t src [4]) {
  return * (uint16_t *) src ;
}
static inline void save16(const uint16_t s, uint8_t dst[4]) {
  uint16_t * d = (uint16_t *) dst ;
  *d = s ;
}

#else

static inline uint64_t load64(const uint8_t src [8]) {
  uint8_t dst[8] ALIGN_64BIT ;
  uint64_t * r = (uint64_t *) dst ;
  dst[ 0] = src[ 7] ;
  dst[ 1] = src[ 6] ;
  dst[ 2] = src[ 5] ;
  dst[ 3] = src[ 4] ;
  dst[ 4] = src[ 3] ;
  dst[ 5] = src[ 2] ;
  dst[ 6] = src[ 1] ;
  dst[ 7] = src[ 0] ;
  return * r ;
}

static inline void save64(const uint64_t s, uint8_t dst[8]) {
  uint8_t * src = (uint8_t *) &s ;
  dst[ 0] = src[ 7] ;
  dst[ 1] = src[ 6] ;
  dst[ 2] = src[ 5] ;
  dst[ 3] = src[ 4] ;
  dst[ 4] = src[ 3] ;
  dst[ 5] = src[ 2] ;
  dst[ 6] = src[ 1] ;
  dst[ 7] = src[ 0] ;
}

static inline uint32_t load32(const uint8_t src [8]) {
  uint8_t dst[4] ALIGN_32BIT ;
  uint32_t * r = (uint32_t *) dst ;
  dst[ 0] = src[ 3] ;
  dst[ 1] = src[ 2] ;
  dst[ 2] = src[ 1] ;
  dst[ 3] = src[ 0] ;
  return * r ;
}

static inline void save32(const uint32_t s, uint8_t dst[8]) {
  uint8_t * src = (uint8_t *) &s ;
  dst[ 0] = src[ 3] ;
  dst[ 1] = src[ 2] ;
  dst[ 2] = src[ 1] ;
  dst[ 3] = src[ 0] ;
}

static inline uint16_t load16(const uint8_t src [8]) {
  uint8_t dst[2] ALIGN_16BIT ;
  uint16_t * r = (uint16_t *) dst ;
  dst[ 0] = src[ 1] ;
  dst[ 1] = src[ 0] ;
  return * r ;
}

static inline void save16(const uint16_t s, uint8_t dst[8]) {
  uint8_t * src = (uint8_t *) &s ;
  dst[ 0] = src[ 1] ;
  dst[ 1] = src[ 0] ;
}

#endif

/* ---------------------------------------------------------
   random sampling
   --------------------------------------------------------- */

static inline void rejsamp_and_q (
  const unsigned int tau,
  uint8_t * dst
){
  for(int i=0; i<tau; i++){ dst[i] &= QRUOV_q ; }
}

static inline void rejsamp_rejection_with_aux(
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

static inline void RejSamp(
  const unsigned int length,
  const unsigned int tau,    // tau = tau(length) > length
        uint8_t *    dst     // dst[tau]
){
  rejsamp_and_q (tau, dst) ;
  rejsamp_rejection_with_aux (length, dst+length, dst) ;
}


/* -----------------------------------------------------
  PRG
   ----------------------------------------------------- */

static EVP_CIPHER_CTX * PRG_init_aes_ctr(const uint8_t seed[QRUOV_SEED_LEN]){
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new() ;
  EVP_EncryptInit_ex(ctx, EVP_AES_CTR(), NULL, seed, NULL) ;
  return ctx ;
}
static void PRG_yield_aes_ctr(EVP_CIPHER_CTX * ctx, int length, uint8_t * dst){
  int out_len ;
  memset(dst, 0, length) ;
  EVP_EncryptUpdate(ctx, dst, &out_len, dst, length) ;
}
static void PRG_final_aes_ctr(EVP_CIPHER_CTX * ctx){ EVP_CIPHER_CTX_free(ctx) ; }
static EVP_CIPHER_CTX * PRG_copy_aes_ctr(EVP_CIPHER_CTX * src){
  EVP_CIPHER_CTX * dst = EVP_CIPHER_CTX_new() ;
  EVP_CIPHER_CTX_copy(dst, src) ;
  return dst ;
}

static EVP_MD_CTX * PRG_init_shake(const uint8_t seed[QRUOV_SEED_LEN]){
  EVP_MD_CTX * ctx = EVP_MD_CTX_new() ;
  EVP_DigestInit_ex(ctx, EVP_SHAKE(), NULL) ;
  EVP_DigestUpdate(ctx, seed, QRUOV_SEED_LEN) ;
  return ctx ;
}
/* PRG_yield_shake() may be called just once in openssl 1.x */
static void PRG_yield_shake(EVP_MD_CTX * ctx, int length, uint8_t * dst){ EVP_DigestFinalXOF(ctx, dst, length) ; }
static void PRG_final_shake(EVP_MD_CTX * ctx){ EVP_MD_CTX_free(ctx) ; }
static EVP_MD_CTX * PRG_copy_shake(EVP_MD_CTX * src){ 
  EVP_MD_CTX * dst = EVP_MD_CTX_new() ;
  EVP_MD_CTX_copy(dst, src) ;
  return dst ;
}

static MGF_CTX_s * PRG_init_mgf(const uint8_t seed[QRUOV_SEED_LEN]){ return MGF_init(seed, QRUOV_SEED_LEN, malloc(sizeof(MGF_CTX))) ; }
static void PRG_yield_mgf(MGF_CTX_s * ctx, int length, uint8_t * dst){ MGF_yield (ctx, dst, length) ; }
static void PRG_final_mgf(MGF_CTX_s * ctx){ MGF_final(ctx) ; free(ctx) ; }
static MGF_CTX_s * PRG_copy_mgf(MGF_CTX_s * src){
  MGF_CTX_s * dst = malloc(sizeof(MGF_CTX)) ;
  MGF_CTX_copy(src, dst) ; 
  return dst ;
}

static inline void RejSampPRG_aes_ctr(
  EVP_CIPHER_CTX *   ctx,
  const uint64_t     index,
  const unsigned int length,
  const unsigned int tau,    // tau = tau(length) > length
        uint8_t *    dst     // dst[tau]
){
  int out_len ;
  uint8_t iv[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0} ;
  save64(index, iv) ;
  EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) ;
  memset(dst, 0, tau) ;
  EVP_EncryptUpdate(ctx, dst, &out_len, dst, tau) ;
  RejSamp(length, tau, dst) ;
}

static inline void RejSampPRG_shake(
  EVP_MD_CTX *       ctx,
  const uint64_t     index,
  const unsigned int length,
  const unsigned int tau,    // tau = tau(length) > length
        uint8_t *    dst     // dst[tau]
){
  uint8_t iv[2] ;
  save16((uint16_t)index, iv) ;
  EVP_DigestUpdate(ctx, iv, 2) ;
  EVP_DigestFinalXOF(ctx, dst, tau) ;
  RejSamp(length, tau, dst) ;
}

/* -------------------------------------------
  Expand_mu(), Hash() -> shake256 only
   ------------------------------------------- */

static void Expand_mu(
  const QRUOV_SEED seed_pk,         // input
  const uint8_t    message[],       // input
  const size_t     message_length,  // input (message)
  uint8_t          mu[QRUOV_MU_LEN] // output mu[64]
){
  EVP_MD_CTX * ctx = EVP_MD_CTX_new() ;
  EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) ;
  EVP_DigestUpdate(ctx, seed_pk, QRUOV_SEED_LEN) ;
  EVP_DigestUpdate(ctx, message, message_length) ;
  EVP_DigestFinalXOF(ctx, mu, QRUOV_MU_LEN) ;
  EVP_MD_CTX_free(ctx) ;
}

static void Hash(
  const uint8_t    mu[QRUOV_MU_LEN], // input
  const QRUOV_SALT salt,             // input
  uint8_t          dst[QRUOV_m]      // output
){
  uint8_t tmp[QRUOV_tau4] ;
  EVP_MD_CTX * ctx = EVP_MD_CTX_new() ;
  EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) ;
  EVP_DigestUpdate(ctx, mu, QRUOV_MU_LEN) ;
  EVP_DigestUpdate(ctx, salt, QRUOV_SALT_LEN) ;
  EVP_DigestFinalXOF(ctx, tmp, QRUOV_tau4) ;
  RejSamp(QRUOV_m, QRUOV_tau4, tmp) ;
  memcpy(dst, tmp, QRUOV_m) ;
  EVP_MD_CTX_free(ctx) ;
  return ;
}

/* -------------------------------------------

   ------------------------------------------- */

static void ExpandVectorV (
  uint8_t * src,  // input src[L*V]
  VECTOR_V    A   // output
) {
  uint8_t * s = src ;
  for(int i=0;i<QRUOV_V;i++) for(int k=0;k<QRUOV_L;k++) A[k][i] = *s++ ;
  VECTOR_V_CLEAR_TAIL(A) ;
}

static void ExpandMatrixVxM (
  uint8_t *  src, // input src[L*V*M]
  MATRIX_VxM   A  // output
) {
  uint8_t * s = src ;
  for(int i=0;i<QRUOV_V;i++){
    for(int j=0;j<QRUOV_M;j++){
      for(int k=0;k<QRUOV_L;k++){
        A[i][k][j] = *s++ ;
      }
    }
    VECTOR_M_CLEAR_TAIL(A[i]) ;
  }
}

static void ExpandSymmetricMatrixVxV (
  uint8_t *  src, // input src[L*V*(V+1)/2]
  MATRIX_VxV   A  // output
){
  uint8_t * s = src ;
  for(int i=0; i<QRUOV_V; i++){
    for(int j=0; j<QRUOV_V; j++){
      if(j<i){
        for(int k=0;k<QRUOV_L;k++) A[i][k][j] = A[j][k][i] ;
      }else{
        for(int k=0;k<QRUOV_L;k++) A[i][k][j] = *s++ ;
      }
    }
    VECTOR_V_CLEAR_TAIL(A[i]) ;
  }
}

/* -------------------------------------------

   ------------------------------------------- */

static void Expand_sk(
  const QRUOV_SEED seed_sk,  // input
  MATRIX_VxM Sd,             // output
  MATRIX_MxV SdT
){
  const int n2 = QRUOV_L * QRUOV_V * QRUOV_M ;
  uint8_t   r2[QRUOV_tau2] ;
  QRUOV_PRG_CTX * ctx = PRG_init(seed_sk) ;
  RejSampPRG(ctx, 0, n2, QRUOV_tau2, r2) ;
  ExpandMatrixVxM(r2, Sd) ;
  MATRIX_TRANSPOSE_VxM(Sd, SdT) ;

  PRG_final(ctx) ;
  OPENSSL_cleanse(r2, QRUOV_tau2) ;
}

static void Expand_pk(
  QRUOV_PRG_CTX * ctx0,  // input
  const uint64_t  index, // input
  MATRIX_VxV      Pi1,   // output
  MATRIX_VxM      Pi2    // output
){
  const int n1 = QRUOV_L * QRUOV_V * (QRUOV_V + 1) / 2 ;
  const int n2 = QRUOV_L * QRUOV_V * QRUOV_M ;
  uint8_t r1[QRUOV_tau1] ;
  uint8_t r2[QRUOV_tau2] ;

  QRUOV_PRG_CTX * ctx1 = PRG_copy(ctx0) ;
  RejSampPRG(ctx1, 2*index, n1, QRUOV_tau1, r1) ;
  ExpandSymmetricMatrixVxV(r1, Pi1) ;
  PRG_final(ctx1) ;

  QRUOV_PRG_CTX * ctx2 = PRG_copy(ctx0) ;
  RejSampPRG(ctx2, 2*index+1, n2, QRUOV_tau2, r2) ;
  ExpandMatrixVxM(r2, Pi2) ;
  PRG_final(ctx2) ;
}

static void Expand_y (
  const QRUOV_SEED seed_y, // input
  VECTOR_V              y  // output
){
  const int n3 = QRUOV_L * QRUOV_V ;
  uint8_t r3[QRUOV_tau3] ;
  QRUOV_PRG_CTX * ctx = PRG_init(seed_y) ;
  RejSampPRG(ctx, 0, n3, QRUOV_tau3, r3) ;
  ExpandVectorV(r3, y) ;
  PRG_final(ctx) ;
}

static void Expand_sol (
  const   QRUOV_SEED seed_sol,  // input
  uint8_t dst[QRUOV_m]          // output
){
  const int n4 = QRUOV_L * QRUOV_M ;
  uint8_t r4[QRUOV_tau4] ;
  QRUOV_PRG_CTX * ctx = PRG_init(seed_sol) ;
  RejSampPRG(ctx, 0, n4, QRUOV_tau4, r4) ;
  memcpy(dst, r4, n4) ;
  PRG_final(ctx) ;
}

/* ---------------------------------------------------------
   Linear Algebra
   --------------------------------------------------------- */

TYPEDEF_STRUCT (ROW,
  Fq * col  ;
  int  original_row_id ;
) ;

TYPEDEF_STRUCT (ECHELON_FORM,
  ROW_s   row   [QRUOV_m] ;
  ROW_s * eqn   [QRUOV_m] ;
  int rank          ;
  int index     [QRUOV_m] ;
) ;

static void echelon_form_init(Fq mat[QRUOV_m][QRUOV_m], ECHELON_FORM echelon_form) {
  for(int i=0;i<QRUOV_m;i++){
    echelon_form->row[i].col             = mat[i] ;
    echelon_form->row[i].original_row_id = i ;
    echelon_form->eqn[i]                 = echelon_form->row + i ;
  }
  echelon_form->rank = 0 ;
  memset(echelon_form->index,-1,sizeof(echelon_form->index));
}

static void row_swap(ROW_s * eqn[QRUOV_m], int i, int j) {
  ROW_s * tmp  = eqn[i] ;
  eqn[i] = eqn[j] ;
  eqn[j] = tmp ;
}

#define EQN(I,J) (eqn[I]->col[J])

static void LU_decompose(
  Fq A[QRUOV_m][QRUOV_m],                    // input (will be destroyed)
  ECHELON_FORM echelon_form      // output
) {
  echelon_form_init(A, echelon_form) ;
  int i,j,k ;
  ROW_s ** eqn = echelon_form->eqn ;

  int c = -1 ;
  for(i=0; i<QRUOV_m; i++) {
    c++ ; if(c >= QRUOV_m) return ;
    j = i ;
    while(EQN(j,c)==0){
      j++ ;
      if(j >= QRUOV_m) {
        c++ ; if(c >= QRUOV_m) return ;
        j = i ;
      }
    }

    row_swap(eqn,i,j) ;
    echelon_form->index[echelon_form->rank++] = c ;

    Fq pivot = EQN(i,c) ;
    Fq inv   = Fq_inv(pivot) ;

    EQN(i,i)  = pivot ;
    for(k = c+1; k<QRUOV_m; k++) EQN(i,k) = Fq_mul(inv, EQN(i,k)) ;

    for(j=i+1; j<QRUOV_m; j++) {
      Fq mul = EQN(j,c) ;
      EQN(j,i) = mul ;

      for(k = c+1; k<QRUOV_m; k++){
        EQN(j,k) = Fq_sub(EQN(j,k), Fq_mul(mul, EQN(i,k))) ;
      }
    }
  }

  return ;
}

static void Fq_mxm_identity(Fq A[QRUOV_m][QRUOV_m]){
  memset(A,0,sizeof(Fq)*QRUOV_m*QRUOV_m) ;
  for(int i=0;i<QRUOV_m;i++) A[i][i] = 1 ;
}

static void L_inverse(ECHELON_FORM echelon_form, Fq R[QRUOV_m][QRUOV_m]){
  ROW_s ** eqn  = echelon_form->eqn  ;
  int      rank = echelon_form->rank ;

  Fq_mxm_identity(R) ;

  for(int i=0;i<rank;i++){
    Fq pivot = EQN(i,i) ;
    Fq inv   = Fq_inv(pivot) ;
    for(int k=0;k<=i;k++) R[i][k] = Fq_mul(R[i][k],inv) ;
    for(int j=i+1;j<QRUOV_m;j++){
      for(int k=0;k<=i;k++){
        R[j][k]  = Fq_sub(R[j][k], Fq_mul(EQN(j,i),R[i][k])) ;
      }
    }
  }
}

static int consistent (
  ECHELON_FORM echelon_form,   // input
  Fq b[QRUOV_m],
  int * cacheR,                // output
  Fq R[QRUOV_m][QRUOV_m]
) {
  ROW_s ** eqn  = echelon_form->eqn  ;
  int      rank = echelon_form->rank ;
  if(rank==QRUOV_m) return 1 ;

  if(*cacheR == 0){
    L_inverse(echelon_form, R) ;
    *cacheR = 1;
  }

  for(int i=rank; i<QRUOV_m; i++){
    int     k ;
    uint64_t t = 0 ;
    for(int j=0; j<rank; j++){
      k = eqn[j]->original_row_id ;
      t += ((uint64_t)R[i][j]) * ((uint64_t)b[k]) ;
    }
    k = eqn[i]->original_row_id ;
    t += ((uint64_t)R[i][i]) * ((uint64_t)b[k]) ;
    t %= QRUOV_q ;
    if(t) return 0 ;
  }

  return 1 ;
}

static void sample_a_solution(
  const QRUOV_SEED seed_sol,     // input
  ECHELON_FORM     echelon_form, // input
  Fq               b  [QRUOV_m], // input
  Fq               x  [QRUOV_m], // output
  Fq               b2 [QRUOV_m]  // output
) {
  int      rank  = echelon_form->rank ;
  int   *  index = echelon_form->index ;
  ROW_s ** eqn   = echelon_form->eqn  ;
  int i,j,k,o ;

  uint8_t random_buff[QRUOV_m] ;
  uint8_t * random_element = random_buff ;
  if(rank < QRUOV_m) Expand_sol (seed_sol, random_buff) ;

  for(i=0; i<rank; i++){
    uint64_t t = 0 ;
    for(j=0;j<i;j++){
      t += ((uint64_t)EQN(i,j)) * ((uint64_t)b2[j]) ;
    }
    Fq tmp = (Fq)(t % QRUOV_q) ;
    k = eqn[i]->original_row_id ;
    tmp = Fq_sub(b[k],tmp) ;
    b2[i] = Fq_mul(tmp,Fq_inv(EQN(i,i))) ;
  }

  i = QRUOV_m-1 ;
  for(j = rank-1; j>=0; j--){
    k = index[j] ;
    for( ; i > k; i--) x[i] = *random_element++ ;
    // i == k
    uint64_t t = 0 ;
    for(k++; k < QRUOV_m; k++){
      t += ((uint64_t)EQN(j,k)) * ((uint64_t)(x[k])) ;
    }
    x[i] = Fq_sub(b2[j], (Fq)(t % QRUOV_q) ) ;
    i-- ;
  }
  for( ; i >= 0; i--) x[i] = *random_element++ ;
  return ;
}

static void pack_0 (Fq oil_u[QRUOV_m], VECTOR_M oil) {
  Fq * s = oil_u ;
  for(int i=0; i<QRUOV_M; i++)
    for(int k=0; k<QRUOV_L; k++)
      oil[k][i] = *s++ ;
}

/* ---------------------------------------------------------
   KeyGen
   --------------------------------------------------------- */

void QRUOV_KeyGen (
  const QRUOV_SEED seed_sk, // input
  const QRUOV_SEED seed_pk, // input
  QRUOV_P3         P3       // output
){
  MATRIX_VxM Sd  ;
  MATRIX_MxV SdT ;
  MATRIX_VxV Pi1 ;
  MATRIX_VxM Pi2 ;
  MATRIX_MxV Pi2T;
  MATRIX_MxV TMP ; // Fi2T

  Expand_sk(seed_sk, Sd, SdT) ;

  QRUOV_PRG_CTX * ctx = PRG_init(seed_pk) ;
  for(int i = 0; i < QRUOV_m; i++){
    Expand_pk(ctx, i, Pi1, Pi2) ;
    MATRIX_TRANSPOSE_VxM(Pi2, Pi2T) ;
//    MATRIX_MUL_MxV_VxV(SdT,Pi1,TMP) ;
    MATRIX_MxV_MUL_SYMMETRIC_MATRIX_VxV (SdT,Pi1,TMP) ;
    MATRIX_SUB_MxV(Pi2T,TMP,TMP) ;
    MATRIX_MUL_MxV_VxM(TMP,Sd,P3[i]) ;
    MATRIX_MUL_ADD_MxV_VxM(SdT,Pi2,P3[i]) ;
  }
  PRG_final(ctx) ; 

  OPENSSL_cleanse(TMP, sizeof(TMP)) ;
  OPENSSL_cleanse(Sd, sizeof(MATRIX_VxM)) ;
  OPENSSL_cleanse(SdT, sizeof(MATRIX_MxV)) ;

  return ;
}

/* ---------------------------------------------------------
   Sign
   --------------------------------------------------------- */

static void SIG_GEN(const VECTOR_M oil, const MATRIX_VxM Sd, const VECTOR_V vineger, QRUOV_SIGNATURE sig){
  for(int i=0;i<QRUOV_V;i++){
    Fq u [QRUOV_L] ;
    for(int j=0;j<QRUOV_L;j++) u[j] = vineger[j][i] ;
    Fq t [QRUOV_L] ;
    VECTOR_M_dot_VECTOR_M(oil, Sd[i], t) ;
    sig->s[i] = Fql_sub(
      Fq2Fql(u),
      Fq2Fql(t)
    ) ;
  }
  for(int i=QRUOV_V;i<QRUOV_N;i++){
    Fq u [QRUOV_L] ;
    for(int j=0;j<QRUOV_L;j++) u[j] = oil[j][i-QRUOV_V] ;
    sig->s[i] = Fq2Fql(u) ;
  }
}

void QRUOV_Sign (
  // ---------------------------------------------------
  const QRUOV_SEED seed_sk,        // input (signing key)
  const QRUOV_SEED seed_pk,        // input (signing key)
  // ---------------------------------------------------
  const QRUOV_SEED seed_y,         // input (seed_y   ->   y:(F_q)^v     )
  const QRUOV_SEED seed_r,         // input (seed_r   ->   r:{0,1}^lambda)
  const QRUOV_SEED seed_sol,       // input (seed_sol -> sol:(F_q)^m     )
  // ---------------------------------------------------
  const uint8_t    message[],      // input (message)
  const size_t     message_length, // input (message)
  // ---------------------------------------------------
  QRUOV_SIGNATURE  sig        // output
) {
  //  int i,j,k,o ;

  ECHELON_FORM echelon_form ;

//  Fql oil     [QRUOV_M] ; //
  VECTOR_M oil ;

  Fq  oil_u   [QRUOV_m] ; // unpacked oil.
  Fq  b       [QRUOV_m] ; //
  Fq  b2      [QRUOV_m] ; //
  Fq  c       [QRUOV_m] ; //

  Fq eqn [QRUOV_m][QRUOV_m] ;
  Fq R   [QRUOV_m][QRUOV_m] ;

  int cacheR        = 0 ;

  Fq msg [QRUOV_m] ;

  /* ----------------------------------
     
     ---------------------------------- */

  MATRIX_VxM Sd              ;
  MATRIX_MxV SdT             ;
  MATRIX_VxV Pi1             ;
  MATRIX_VxM Pi2             ;
  VECTOR_V   y               ; // vineger
  vector_V * yT = y          ;
  VECTOR_V   yT_Pi1          ;
  vector_V * yT_Fi1 = yT_Pi1 ;
  VECTOR_M   yT_Pi1_Sd       ;
  VECTOR_M   yT_Pi2          ;
  VECTOR_M   yT_Fi2          ;

  Expand_sk(seed_sk, Sd, SdT) ;
  Expand_y (seed_y, yT) ;

  QRUOV_PRG_CTX * ctx_pk = PRG_init(seed_pk) ;
  for(int i = 0; i < QRUOV_m; i++){
    Expand_pk(ctx_pk, i, Pi1, Pi2) ;

    VECTOR_V_MUL_SYMMETRIC_MATRIX_VxV(yT, Pi1, yT_Pi1) ;
    VECTOR_V_MUL_MATRIX_VxM(yT_Pi1, Sd, yT_Pi1_Sd) ;
    VECTOR_V_MUL_MATRIX_VxM(yT, Pi2, yT_Pi2) ;
    VECTOR_M_SUB(yT_Pi2, yT_Pi1_Sd, yT_Fi2) ;

    // EQN_GEN

    for(int j=0; j<QRUOV_M; j++){
      for(int k=0; k<QRUOV_L; k++){
        Fq u = yT_Fi2[QRUOV_perm(k)][j] ;
        eqn[i][QRUOV_L*j+k] = Fq_add(u,u) ; // <- unpack_1(...)
      }
    }

    // C_GEN c[i] <- yT_Fi1 . y

    {
      uint64_t c_i = 0 ;
      for(int j=0; j<QRUOV_V; j++){
	Fq yT_Fi1_j[QRUOV_L] ;
	Fq y_j     [QRUOV_L] ;
        for(int k=0; k<QRUOV_L; k++) yT_Fi1_j[k] = yT_Fi1[k][j] ;
        for(int k=0; k<QRUOV_L; k++) y_j     [k] = y     [k][j] ;
        c_i += (uint64_t) Fql2Fq(Fql_mul(Fq2Fql(yT_Fi1_j), Fq2Fql(y_j)), QRUOV_perm(0)) ; // <-- shrink
      }
      c[i] = (Fq)(c_i % QRUOV_q) ;
    }
  }
  PRG_final(ctx_pk) ;

  LU_decompose(eqn, echelon_form) ;

  uint8_t mu [QRUOV_MU_LEN] ;
  Expand_mu(seed_pk, message, message_length, mu) ;

  QRUOV_PRG2_CTX * ctx_r = PRG2_init(seed_r) ;
  do{
    PRG2_yield(ctx_r, QRUOV_SALT_LEN, sig->r) ;
    Hash(mu, sig->r, msg) ;
    for(int i=0; i<QRUOV_m; i++) b[i] = Fq_sub(msg[i], c[i]) ;
  }while(!consistent(echelon_form, b, &cacheR, R)) ;
  PRG2_final(ctx_r) ;

  sample_a_solution(seed_sol, echelon_form, b, oil_u, b2) ;

  pack_0(oil_u, oil) ;

  SIG_GEN(oil, Sd, y, sig) ;

  OPENSSL_cleanse(Sd, sizeof(MATRIX_VxM)) ;
  OPENSSL_cleanse(SdT, sizeof(MATRIX_MxV)) ;

  return ;
}

/* ---------------------------------------------------------
   Verify
   --------------------------------------------------------- */

static uint8_t VERIFY_i(const MATRIX_VxV Pi1, const MATRIX_VxM Pi2, const MATRIX_MxM Pi3, const VECTOR_M oil, const VECTOR_V vineger, const Fq msg_i){
  int j,k ;

  VECTOR_V tmp_v ;
  VECTOR_M tmp_o ;

  Fq t [QRUOV_L] ;
  Fq u [QRUOV_L] ;

  for(j=0;j<QRUOV_V;j++){
      VECTOR_M_dot_VECTOR_M(oil, Pi2[j], t) ;
      VECTOR_V_dot_VECTOR_V(vineger, Pi1[j], u) ;
      for(k=0;k<QRUOV_L;k++) tmp_v[k][j] = Fq_add(Fq_add(t[k],t[k]),u[k]) ;
  }

  for(j=0;j<QRUOV_M;j++){
      VECTOR_M_dot_VECTOR_M(oil, Pi3[j], t) ;
      for(k=0;k<QRUOV_L;k++) tmp_o[k][j] = t[k] ;
  }

  VECTOR_V_dot_VECTOR_V(vineger, tmp_v, t) ;
  VECTOR_M_dot_VECTOR_M(oil    , tmp_o, u) ;

  return msg_i == Fq_add(t[QRUOV_perm(0)],u[QRUOV_perm(0)]) ;
}

int QRUOV_Verify(
  const QRUOV_SEED       seed_pk,        // input
  const QRUOV_P3         P3,             // input
  const uint8_t          message[],      // input (message)
  const size_t           message_length, // input (message)
  const QRUOV_SIGNATURE  sig             // input
) {

  uint8_t mu [QRUOV_MU_LEN] ;
  Expand_mu(seed_pk, message, message_length, mu) ;
  Fq msg [QRUOV_m] ;
  Hash(mu, sig->r, msg) ;

  MATRIX_VxV Pi1  ;
  MATRIX_VxM Pi2  ;

  const Fql * y_   = sig->s           ; // vineger
  const Fql * oil_ = sig->s + QRUOV_V ; // oil

  VECTOR_V y   ;
  VECTOR_M oil ;

  for(int i=0; i<QRUOV_V; i++,y_++)
    for(int k=0; k<QRUOV_L; k++)
      y[k][i] = Fql2Fq(*y_,k) ;
  VECTOR_V_CLEAR_TAIL(y) ;


  for(int i=0; i<QRUOV_M; i++,oil_++)
    for(int k=0; k<QRUOV_L; k++)
      oil[k][i] = Fql2Fq(*oil_,k) ;
  VECTOR_M_CLEAR_TAIL(oil) ;

  int verify = 1 ;

  QRUOV_PRG_CTX * ctx_pk = PRG_init(seed_pk) ;
  for(int i=0;i<QRUOV_m;i++){
    Expand_pk(ctx_pk, i, Pi1, Pi2) ;
    verify &= VERIFY_i(Pi1, Pi2, P3[i], oil, y, msg[i]) ;
    if(! verify) break ;
  }
  PRG_final(ctx_pk) ;
  return verify ;
}

/* ---------------------------------------------------------
   memory I/O
   --------------------------------------------------------- */

void store_QRUOV_P3(
  const QRUOV_P3   P3,       // input
  uint8_t        * pool,     // output
  size_t         * pool_bits // input/output (current bit index)
){
  for(int i=0; i<QRUOV_m; i++){
    for(int j=0; j<QRUOV_M; j++){
      for(int k=0; k<QRUOV_M; k++){
        if(k<j){
          // do nothing
          // if(P3[i][j][k] != P3[i][k][j]){ printf("error\n"); };
	}else{
          for(int n=0; n<QRUOV_L; n++){
            store_Fq(P3[i][j][n][k], pool, pool_bits) ;
	  }
        }
      }
    }
  }
}

void restore_QRUOV_P3(
  const uint8_t * pool,      // input
  size_t        * pool_bits, // input/output (current bit index)
  QRUOV_P3        P3         // output
){
  for(int i=0; i<QRUOV_m; i++){
    for(int j=0; j<QRUOV_M; j++){
      for(int k=0; k<QRUOV_M; k++){
        if(k<j){
          for(int n=0; n<QRUOV_L; n++) P3[i][j][n][k] = P3[i][k][n][j] ;
        }else{
          for(int n=0; n<QRUOV_L; n++) P3[i][j][n][k] = restore_Fq(pool, pool_bits) ;
        }
      }
    }
  }
}
