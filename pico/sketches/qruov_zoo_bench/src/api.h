#pragma once

#include "qruov.h"

//  Set these three values apropriately for your algorithm
#ifndef CRYPTO_SECRETKEYBYTES
#define CRYPTO_SECRETKEYBYTES 32
#endif
#ifndef CRYPTO_PUBLICKEYBYTES
#define CRYPTO_PUBLICKEYBYTES 24256
#endif
#ifndef CRYPTO_BYTES
#define CRYPTO_BYTES          200
#endif

// Change the algorithm name
#ifndef CRYPTO_ALGNAME
#define CRYPTO_ALGNAME "qruov-zoo"
#endif

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int
crypto_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);
