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
#ifdef WB_CHECKS  /* mqtt_tls_bench -DMT_DEPLOY: what a deployed client checks besides the chain */
    #define WB_ASN_TIME            /* certificate and CRL dates, on time() set by NTP (needs make_wolfssl_lib.sh's patch) */
    #define HAVE_CRL               /* revocation lists (wolfSSL_CTX_LoadCRLBuffer) */
    #define WOLFSSL_IP_ALT_NAME    /* wolfSSL_check_domain_name matches the broker's IP in the certificate */
#else
    #define NO_ASN_TIME            /* the benchmark firmware: chain only, no clock on the board */
#endif
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

/* -DWB_SNOVA<1K|1B|1S|3K|3B|3S|5K|5B|5S> (with -DWB_TLS; certs/round3/SNOVA<set>): round 3 SNOVA certificates, which
 * wolfSSL doesn't have, in Falcon-512's place. make_wolfssl_lib.sh makes Falcon-512's OID sum, OID, TLS codepoint and sizes
 * the WB_FALCON1_* values below and swaps falcon.c for wb_snova.c (liboqs main's SNOVA: the arduino-libs-r3 library),
 * so wolfSSL's own certificate and TLS 1.3 code for Falcon carries SNOVA. Per set (oqs-provider 36cafae / liboqs main):
 * the OID 1.3.9999.10.<n>.3, its sum (wc_oid_sum), the codepoint 0xFF<minor>, public key and signature bytes. */
#if   defined(WB_SNOVA1K)
    #define WB_SNOVA_SET I_K
    #define WB_SNOVA_N 1, 0x0af0cd2a, 0x83,  376, 528
#elif defined(WB_SNOVA1B)
    #define WB_SNOVA_SET I_B
    #define WB_SNOVA_N 2, 0x0af0cd29, 0x85,  656, 388
#elif defined(WB_SNOVA1S)
    #define WB_SNOVA_SET I_S
    #define WB_SNOVA_N 3, 0x0af0cd28, 0x87, 1016, 272
#elif defined(WB_SNOVA3K)
    #define WB_SNOVA_SET III_K
    #define WB_SNOVA_N 4, 0x0af0cd2f, 0x89,  912, 688
#elif defined(WB_SNOVA3B)
    #define WB_SNOVA_SET III_B
    #define WB_SNOVA_N 5, 0x0af0cd2e, 0x8b, 1416, 532
#elif defined(WB_SNOVA3S)
    #define WB_SNOVA_SET III_S
    #define WB_SNOVA_N 6, 0x0af0cd2d, 0x8d, 2032, 456
#elif defined(WB_SNOVA5K)
    #define WB_SNOVA_SET V_K
    #define WB_SNOVA_N 7, 0x0af0cd2c, 0x8f, 1216, 896
#elif defined(WB_SNOVA5B)
    #define WB_SNOVA_SET V_B
    #define WB_SNOVA_N 8, 0x0af0cd23, 0x91, 1891, 691
#elif defined(WB_SNOVA5S)
    #define WB_SNOVA_SET V_S
    #define WB_SNOVA_N 9, 0x0af0cd22, 0x93, 2716, 591
#endif
#define WB_SN_ARG(i, n, sum, minor, pk, sig) WB_SN_##i(n, sum, minor, pk, sig)
#define WB_SN_GET(i, ...) WB_SN_ARG(i, __VA_ARGS__)
#define WB_SN_ARC(n, sum, minor, pk, sig) n
#define WB_SN_SUM(n, sum, minor, pk, sig) sum
#define WB_SN_MINOR(n, sum, minor, pk, sig) minor
#define WB_SN_PK(n, sum, minor, pk, sig) pk
#define WB_SN_SIG(n, sum, minor, pk, sig) sig
#ifdef WB_SNOVA_SET
    #define WB_SNOVA
    #define HAVE_FALCON
    #define WOLFSSL_EXPERIMENTAL_SETTINGS
    #define WB_SNOVA_PK  WB_SN_GET(PK, WB_SNOVA_N)
    #define WB_SNOVA_SK  96             /* every set: seeds */
    #define WB_SNOVA_SIG WB_SN_GET(SIG, WB_SNOVA_N)
    #define WB_FALCON1_SUM      WB_SN_GET(SUM, WB_SNOVA_N)
    #define WB_FALCON1_OID      43, 206, 15, 10, WB_SN_GET(ARC, WB_SNOVA_N), 3
    #define WB_FALCON1_SA_MAJOR 0xFF
    #define WB_FALCON1_SA_MINOR WB_SN_GET(MINOR, WB_SNOVA_N)
    #define WB_FALCON1_KEY_SIZE WB_SNOVA_SK
    #define WB_FALCON1_PUB_SIZE WB_SNOVA_PK
    #define WB_FALCON1_SIG_SIZE WB_SNOVA_SIG
    #define WB_FALCON_MAX_PUB   2716        /* SNOVA_V_S's: more than Falcon-1024's 1,793 */
    #define MIN_FALCONKEY_SZ    WB_SNOVA_SK /* wolfSSL's minimum is Falcon-512's 1,281 B secret key */
    #define WOLFSSL_MAX_SIGALGO 256         /* the round 3 broker offers 80 signature algorithms (160 B): wolfSSL's
                                             * 128 B cut its list before SNOVA level V's */
#else  /* wolfSSL's own Falcon-512 (1.3.9999.3.11) */
    #define WB_FALCON1_SUM      0x7c0f3120
    #define WB_FALCON1_OID      43, 206, 15, 3, 11
    #define WB_FALCON1_SA_MAJOR 0xFE
    #define WB_FALCON1_SA_MINOR 0xD7
    #define WB_FALCON1_KEY_SIZE 1281
    #define WB_FALCON1_PUB_SIZE 897
    #define WB_FALCON1_SIG_SIZE 666
    #define WB_FALCON_MAX_PUB   1793
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
    #elif defined(__ARM_ARCH_8M_MAIN__)
        #define WOLFSSL_SP_ARM_CORTEX_M_ASM /* RP2350 Cortex-M33 */
    #endif                                 /* else (pico/tests/deploy_host_test on the Mac / Pi): portable C */
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
