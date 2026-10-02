/* ecx_shim.h - replaces OpenSSL's <crypto/ecx.h>: just the public X448/Ed448 prototypes
 *   that curve448.c / eddsa.c define, plus the ones our wrapper calls. */
#ifndef ECX_SHIM_H
#define ECX_SHIM_H

#include <stdint.h>
#include <stddef.h>
#include "ossl_compat.h"   /* OSSL_LIB_CTX */

int  ossl_x448(uint8_t out_shared_key[56], const uint8_t private_key[56],
               const uint8_t peer_public_value[56]);
void ossl_x448_public_from_private(uint8_t out_public_value[56],
                                   const uint8_t private_key[56]);

int ossl_ed448_sign(OSSL_LIB_CTX *ctx, uint8_t *out_sig,
                    const uint8_t *message, size_t message_len,
                    const uint8_t public_key[57], const uint8_t private_key[57],
                    const uint8_t *context, size_t context_len,
                    const uint8_t phflag, const char *propq);
int ossl_ed448_verify(OSSL_LIB_CTX *ctx,
                      const uint8_t *message, size_t message_len,
                      const uint8_t signature[114], const uint8_t public_key[57],
                      const uint8_t *context, size_t context_len,
                      const uint8_t phflag, const char *propq);
int ossl_ed448_pubkey_verify(const uint8_t *pub, size_t pub_len);
int ossl_ed448_public_from_private(OSSL_LIB_CTX *ctx, uint8_t out_public_key[57],
                                   const uint8_t private_key[57], const char *propq);

#endif /* ECX_SHIM_H */
