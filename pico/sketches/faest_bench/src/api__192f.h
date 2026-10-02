#include "faest_config_pico.h"
/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef CRYPTO_SIGN_192F_H
#define CRYPTO_SIGN_192F_H

#define CRYPTO_SECRETKEYBYTES 40
#define CRYPTO_PUBLICKEYBYTES 48
#define CRYPTO_BYTES 14948
#define CRYPTO_ALGNAME "faest_192f"

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk);
int crypto_sign(unsigned char* sm, unsigned long long* smlen, const unsigned char* m,
                unsigned long long mlen, const unsigned char* sk);
int crypto_sign_open(unsigned char* m, unsigned long long* mlen, const unsigned char* sm,
                     unsigned long long smlen, const unsigned char* pk);

#endif

// vim: ft=c
