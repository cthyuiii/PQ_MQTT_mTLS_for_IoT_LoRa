// hs_timing.c - times the crypto a wolfSSL TLS 1.3 client does inside each handshake, in the same run. The linker's
//   -Wl,--wrap=<f> sends wolfSSL's calls to <f> to __wrap_<f> here, which clocks __real_<f> (the wolfCrypt function)
//   and adds it to one of four sums (hs_timing.h), reset per connection:
//     keygen  the client's key share: ML-KEM key pair, X25519 / X448 / ECDH key pair (a hybrid makes two)
//     derive  completing it: ML-KEM decapsulation, X25519 / X448 / ECDH shared secret
//     verify  signature checks: the broker's certificate (the CA's signature, per certificate in the chain) and its
//             CertificateVerify
//     sign    the client's CertificateVerify (mTLS)
//   Only the outermost call counts (depth). __real_<f> is weak: a build without that algorithm never calls it.
//   The wrapped names are the WRAP() lines below; run_benchmarks.py (Pico) and build_timer.sh (Linux, static
//   wolfSSL) read them from this file for the --wrap flags. macOS's linker has no --wrap: no columns there.
#include <stdint.h>
#ifndef ARDUINO
#include <wolfssl/options.h>  // the host build's configure settings
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include "hs_timing.h"

#ifdef ARDUINO
#include <hardware/timer.h>
static double now_us(void) { return (double)time_us_64(); }
#else
#include <time.h>
static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }
#endif

hs_times_t hs_t;
static int depth;

#define WRAP(cat, name, params, args)                                                   \
  extern int __real_##name params __attribute__((weak));                                \
  int __wrap_##name params {                                                            \
    double t0 = depth++ ? 0 : now_us();                                                 \
    int r = __real_##name args;                                                         \
    if (--depth == 0) { hs_t.us[cat] += now_us() - t0; hs_t.n[cat]++; }                 \
    return r;                                                                           \
  }
typedef const byte cb;  // key and RNG pointers stay void *: only their width matters to the call
WRAP(HS_KEYGEN, wc_MlKemKey_MakeKey, (void *k, void *rng), (k, rng))
WRAP(HS_DERIVE, wc_MlKemKey_Decapsulate, (void *k, unsigned char *ss, const unsigned char *ct, word32 l), (k, ss, ct, l))
WRAP(HS_KEYGEN, wc_curve25519_make_key, (void *rng, int ks, void *k), (rng, ks, k))
WRAP(HS_DERIVE, wc_curve25519_shared_secret_ex, (void *a, void *b, byte *o, word32 *ol, int e), (a, b, o, ol, e))
WRAP(HS_KEYGEN, wc_curve448_make_key, (void *rng, int ks, void *k), (rng, ks, k))
WRAP(HS_DERIVE, wc_curve448_shared_secret_ex, (void *a, void *b, byte *o, word32 *ol, int e), (a, b, o, ol, e))
WRAP(HS_KEYGEN, wc_ecc_make_key_ex, (void *rng, int ks, void *k, int id), (rng, ks, k, id))
WRAP(HS_DERIVE, wc_ecc_shared_secret, (void *a, void *b, byte *o, word32 *ol), (a, b, o, ol))
WRAP(HS_VERIFY, wc_ecc_verify_hash, (cb *s, word32 sl, cb *h, word32 hl, int *res, void *k), (s, sl, h, hl, res, k))
WRAP(HS_SIGN, wc_ecc_sign_hash, (cb *in, word32 il, byte *o, word32 *ol, void *rng, void *k), (in, il, o, ol, rng, k))
WRAP(HS_VERIFY, wc_RsaSSL_VerifyInline, (byte *in, word32 il, byte **o, void *k), (in, il, o, k))
WRAP(HS_VERIFY, wc_RsaPSS_VerifyInline, (byte *in, word32 il, byte **o, enum wc_HashType h, int mgf, void *k),
     (in, il, o, h, mgf, k))
WRAP(HS_SIGN, wc_RsaSSL_Sign, (cb *in, word32 il, byte *o, word32 ol, void *k, void *rng), (in, il, o, ol, k, rng))
WRAP(HS_SIGN, wc_RsaPSS_Sign, (cb *in, word32 il, byte *o, word32 ol, enum wc_HashType h, int mgf, void *k, void *rng),
     (in, il, o, ol, h, mgf, k, rng))
WRAP(HS_VERIFY, wc_ed25519_verify_msg, (cb *s, word32 sl, cb *m, word32 ml, int *res, void *k), (s, sl, m, ml, res, k))
WRAP(HS_SIGN, wc_ed25519_sign_msg, (cb *in, word32 il, byte *o, word32 *ol, void *k), (in, il, o, ol, k))
WRAP(HS_VERIFY, wc_MlDsaKey_Verify, (void *k, cb *s, word32 sl, cb *m, word32 ml, int *res), (k, s, sl, m, ml, res))
WRAP(HS_VERIFY, wc_MlDsaKey_VerifyCtx, (void *k, cb *s, word32 sl, cb *c, byte cl, cb *m, word32 ml, int *res),
     (k, s, sl, c, cl, m, ml, res))
WRAP(HS_SIGN, wc_MlDsaKey_SignCtx, (void *k, cb *c, byte cl, byte *s, word32 *sl, cb *m, word32 ml, void *rng),
     (k, c, cl, s, sl, m, ml, rng))
WRAP(HS_VERIFY, wc_falcon_verify_msg, (cb *s, word32 sl, cb *m, word32 ml, int *res, void *k), (s, sl, m, ml, res, k))
WRAP(HS_SIGN, wc_falcon_sign_msg, (cb *in, word32 il, byte *o, word32 *ol, void *k, void *rng), (in, il, o, ol, k, rng))
