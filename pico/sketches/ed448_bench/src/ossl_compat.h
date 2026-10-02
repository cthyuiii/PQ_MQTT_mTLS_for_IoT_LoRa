/* ossl_compat.h - minimal OpenSSL shim for the curve448/Ed448 port (RP2040/RP2350).
 *   Replaces <openssl/e_os2.h>, <openssl/crypto.h>, <openssl/types.h>,
 *   <openssl/macros.h>, internal/numbers.h, internal/e_os.h.
 *   IMPORTANT: it deliberately does NOT define INT128_MAX / UINT128_MAX, which forces
 *   the portable 32-bit field path (f_impl32.c #else branch) on every target. */
#ifndef OSSL_COMPAT_H
#define OSSL_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

/* OpenSSL marks small header functions with 'ossl_inline'. Every use in the
 * curve448 tree is 'static ossl_inline', so map it to plain inline. */
#ifndef ossl_inline
#define ossl_inline inline
#endif

#ifndef OPENSSL_cleanse
#define OPENSSL_cleanse(p, n) memset((void *)(p), 0, (n))
#endif

/* OpenSSL's "warn unused result" attribute (from e_os2.h) - drop it. */
#ifndef __owur
#define __owur
#endif

/* constant_time.h declares value_barrier_bn(BN_ULONG) unconditionally; the curve448
 * code never calls it, but the signature must still parse. */
typedef uintptr_t BN_ULONG;

/* ed448.h prototypes take an OSSL_LIB_CTX* (always passed NULL here). */
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

#endif /* OSSL_COMPAT_H */
