/* api.h - NIST-style signature API for the Ed448 (RFC 8032) port.
 *   sk = seed(57) || public(57) so signing needs no re-derivation; pk = public(57);
 *   detached signature = 114 bytes (R||S). */
#ifndef API_H
#define API_H

#define CRYPTO_SECRETKEYBYTES 114
#define CRYPTO_PUBLICKEYBYTES 57
#define CRYPTO_BYTES          114
#define CRYPTO_ALGNAME        "Ed448"

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif /* API_H */
