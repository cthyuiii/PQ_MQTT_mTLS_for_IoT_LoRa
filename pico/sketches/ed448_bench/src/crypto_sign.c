/* crypto_sign.c - NIST crypto_sign_* wrapper over OpenSSL's ossl_ed448_* (RFC 8032 pure Ed448).
 *   phflag = 0 and context = "" (the pure Ed448 mode). randombytes() is provided by the
 *   sketch (.ino) on-device, or by the host test harness. */
#include <string.h>
#include "api.h"
#include "shake_shim.h"   /* pulls OSSL_LIB_CTX + EVP types before ed448.h */
#include "ed448.h"
#include "ecx_shim.h"

extern int randombytes(unsigned char *x, unsigned long long xlen);

#define ED_SEED 57
#define ED_PUB  57
#define ED_SIG  114

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    randombytes(sk, ED_SEED);                                  /* 57-byte private seed */
    if (!ossl_ed448_public_from_private(NULL, pk, sk, NULL))
        return -1;
    memcpy(sk + ED_SEED, pk, ED_PUB);                          /* cache pub for fast signing */
    return 0;
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    memmove(sm + ED_SIG, m, (size_t)mlen);
    if (!ossl_ed448_sign(NULL, sm, sm + ED_SIG, (size_t)mlen,
                         sk + ED_SEED, sk, NULL, 0, /*phflag*/0, NULL))
        return -1;
    *smlen = mlen + ED_SIG;
    return 0;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    unsigned long long ml;
    if (smlen < ED_SIG)
        return -1;
    ml = smlen - ED_SIG;
    if (!ossl_ed448_verify(NULL, sm + ED_SIG, (size_t)ml, sm, pk, NULL, 0, /*phflag*/0, NULL))
        return -1;
    memmove(m, sm + ED_SIG, (size_t)ml);
    *mlen = ml;
    return 0;
}
