/* wolfssl_user_settings.h - wolfSSL config for pico/sketches/wolfssl_bench and pico/sketches/mqtt_tls_bench (RP2040 / RP2350).
 * make_wolfssl_lib.sh copies it into the generated Arduino library as src/user_settings.h.
 *
 * The runner builds one algorithm per firmware (-DWB_<ALG>) and only that algorithm is enabled
 * below, so each .uf2 size is that scheme's firmware cost (project plan 4.2). Embedded choices
 * follow wolfSSL's guidance: big buffers on the heap (WOLFSSL_SMALL_STACK) instead of the 8 KB
 * arduino-pico stack, ML-DSA / SLH-DSA small-memory code paths, and the Cortex-M bignum assembly
 * for ECDSA/RSA (sp_armthumb.c on the M0+, sp_cortexm.c on the M33).
 */
#ifndef WB_USER_SETTINGS_H
#define WB_USER_SETTINGS_H

#define WOLFSSL_USER_SETTINGS_ID "IoT-PQC pico/sketches/wolfssl_bench"
#ifndef WB_TLS
    #define WOLFCRYPT_ONLY
#endif
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_ASN_TIME
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* RNG: the chip's hardware entropy via rp2040.hwrand32(), wb_rand_block() in the sketch */
#ifdef __cplusplus
extern "C" {
#endif
int wb_rand_block(unsigned char *output, unsigned int sz);
#ifdef __cplusplus
}
#endif
#define CUSTOM_RAND_GENERATE_BLOCK wb_rand_block

/* Hardening, as the Pi / Mac ./configure build (--enable-harden is its default). wolfSSL's settings.h
 * defines HAVE_ECC for every Arduino build, so without these every file warns "consider using harden
 * options", even in ML-DSA-only firmware. They only change the ECC / RSA code paths. */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#if defined(WB_MLDSA44) || defined(WB_MLDSA65) || defined(WB_MLDSA87)
    #define WOLFSSL_HAVE_MLDSA
    #define WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM
    #define WOLFSSL_MLDSA_SIGN_SMALL_MEM
    #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
    #ifndef WB_MLDSA44
        #define WOLFSSL_NO_ML_DSA_44
    #endif
    #ifndef WB_MLDSA65
        #define WOLFSSL_NO_ML_DSA_65
    #endif
    #ifndef WB_MLDSA87
        #define WOLFSSL_NO_ML_DSA_87
    #endif
#endif

#if defined(WB_FALCON512) || defined(WB_FALCON1024)  /* wolfSSL's native Falcon (both levels): portable integer
                                                     * float emulation (no double FPU on either chip) */
    #define HAVE_FALCON
    #define WOLFSSL_FALCON_SIGN_SMALL_MEM
    #define WOLFSSL_EXPERIMENTAL_SETTINGS
#endif

#if defined(WB_SLHDSA_SHA2_128F) || defined(WB_SLHDSA_SHA2_128S) || \
    defined(WB_SLHDSA_SHAKE_128F) || defined(WB_SLHDSA_SHAKE_128S)
    #define WOLFSSL_HAVE_SLHDSA
    #define WOLFSSL_SLHDSA_SHA2
    #define WOLFSSL_WC_SLHDSA_SMALL_MEM
#endif

/* SP math + Cortex-M asm: ECDSA / RSA, and every TLS build (the sweep's P-256 / P-384 / P-521 key shares) */
#if defined(WB_ECDSA_P256) || defined(WB_RSA2048) || defined(WB_RSA3072) || defined(WB_TLS)
    #define WOLFSSL_SP_MATH_ALL
    #define WOLFSSL_SP_SMALL
    #if defined(__ARM_ARCH_6M__)
        #define WOLFSSL_SP_ARM_THUMB_ASM   /* RP2040 Cortex-M0+ */
    #else
        #define WOLFSSL_SP_ARM_CORTEX_M_ASM /* RP2350 Cortex-M33 */
    #endif
#endif
#if defined(WB_ECDSA_P256) || defined(WB_TLS)
    #define HAVE_ECC
    #define WOLFSSL_HAVE_SP_ECC
#endif
#if defined(WB_RSA2048) || defined(WB_RSA3072)
    #define WOLFSSL_KEY_GEN
    #define WOLFSSL_HAVE_SP_RSA
    #define WC_RSA_PSS                      /* TLS 1.3 signs with RSA-PSS */
    #ifndef WB_RSA3072
        #define WOLFSSL_SP_NO_3072
    #endif
    #define WOLFSSL_SP_NO_4096
#else
    #define NO_RSA
#endif
#ifdef WB_ED25519
    #define HAVE_ED25519
    #define HAVE_CURVE25519
    #ifdef WB_SMALL_25519            /* wolfSSL's small, slow curve code (see WB_TLS below); default: its normal code */
        #define CURVED25519_SMALL
    #endif
#endif

#ifdef WB_TLS  /* TLS 1.3's AES-GCM record protection */
    #define HAVE_AESGCM
    #define GCM_TABLE_4BIT
    #define WOLFSSL_AES_128
    #define WOLFSSL_AES_256
#else
    #define NO_AES
#endif

/* -DWB_TLS (pico/sketches/mqtt_tls_bench): a TLS 1.3 client. Stage 2 and the pipeline use X25519MLKEM768 (the customer's),
 * as the host clients; the sweep blocks every ML-KEM group of mqtt_bench.SWEEP_GROUPS (pure, the IETF and
 * the oqs-provider hybrids) and X25519 / P-256. The certificate's algorithm comes from its own block above
 * (-DWB_ECDSA_P256, -DWB_MLDSA44, ...). The sketch moves the bytes over WiFiClient (WOLFSSL_USER_IO callbacks). */
#ifdef WB_TLS
    #define WOLFSSL_TLS13
    #define WOLFSSL_NO_TLS12
    #define NO_OLD_TLS
    #define NO_WOLFSSL_SERVER
    #define NO_SESSION_CACHE
    #define WOLFSSL_USER_IO
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_HKDF
    #define WOLFSSL_SHA384                  /* TLS13-AES256-GCM-SHA384, the suite the host clients get */
    #define HAVE_CURVE25519
    #ifdef WB_SMALL_25519  /* -DWB_SMALL_25519: wolfSSL's small Curve25519 / X448 code. It cost the Pico 424 ms per
                            * X25519 operation against 57 ms (the 1 Oct KEM exchange A/B), for a few KB of flash. */
        #define CURVE25519_SMALL
    #endif
    #define WOLFSSL_HAVE_MLKEM
    #define WOLFSSL_PQC_HYBRIDS             /* X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 */
    #define WOLFSSL_EXTRA_PQC_HYBRIDS       /* oqs-provider's: P-256 / X25519 + 512, P-384 / X448 + 768, P-521 + 1024 */
    #define HAVE_CURVE448
    #ifdef WB_SMALL_25519
        #define CURVE448_SMALL
    #endif
    #define WOLFSSL_SP_384
    #define WOLFSSL_SP_521
    #define WOLFSSL_MLKEM_SMALL
    #define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
    #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
#endif

#endif /* WB_USER_SETTINGS_H */
