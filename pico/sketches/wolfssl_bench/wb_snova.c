/* wb_snova.c - round 3 SNOVA in wolfSSL, in Falcon-512's place (-DWB_SNOVA<set>, wolfssl_user_settings.h).
 * make_wolfssl_lib.sh copies this file next to falcon.c, compiles falcon.c out under WB_SNOVA, and gives Falcon-512's
 * constants (OID, OID sum, TLS codepoint, sizes) SNOVA's. This file is the wc_falcon_* API that wolfSSL's certificate
 * and TLS 1.3 code call, over liboqs main's SNOVA (the arduino-libs-r3 library on the Pico, liboqs-r3 on a host):
 *   keys       oqs-provider's encodings: the public key raw in the certificate, the private key (PKCS#8) sk || pk
 *   sign       OQS_SIG_snova_SNOVA_<set>_sign, its randomness from the TLS connection's WC_RNG
 *   verify     OQS_SIG_snova_SNOVA_<set>_verify
 * Not here (not used by a TLS client): key generation, exporting the private key. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && defined(WB_SNOVA)
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef ARDUINO
#include <liboqs.h>  /* the library's top header: what lets arduino-cli find it */
#else
#include <oqs/oqs.h>
#endif

#define SN_CAT(a, b, c) a##b##c
#define SN_FN(set, op) SN_CAT(OQS_SIG_snova_SNOVA_, set, op)
#define SN_SIGN   SN_FN(WB_SNOVA_SET, _sign)
#define SN_VERIFY SN_FN(WB_SNOVA_SET, _verify)
#define SN_LEN(set, x) SN_CAT(OQS_SIG_snova_SNOVA_, set, x)
/* the sizes wolfssl_user_settings.h gave falcon.h must be liboqs's */
typedef char sn_pk_size[SN_LEN(WB_SNOVA_SET, _length_public_key) == WB_SNOVA_PK ? 1 : -1];
typedef char sn_sk_size[SN_LEN(WB_SNOVA_SET, _length_secret_key) == WB_SNOVA_SK ? 1 : -1];
typedef char sn_sig_size[SN_LEN(WB_SNOVA_SET, _length_signature) == WB_SNOVA_SIG ? 1 : -1];

/* around each signature: the firmware's hooks (mqtt_tls_bench feeds its 8 s watchdog meanwhile: one call signs, and a
 * SNOVA retry doubles a level V signature to ~9.8 s on the RP2040); nothing on a host */
__attribute__((weak)) void wb_snova_sign_begin(void) {}
__attribute__((weak)) void wb_snova_sign_end(void) {}

static WC_RNG *sn_rng;  /* single-threaded: the RNG of the signature in progress */
static void sn_randombytes(uint8_t *out, size_t n) {
    if (wc_RNG_GenerateBlock(sn_rng, out, (word32)n) != 0) XMEMSET(out, 0, n);  /* then sign fails below */
}

int wc_falcon_init_ex(falcon_key *key, void *heap, int devId) {
    if (key == NULL) return BAD_FUNC_ARG;
    XMEMSET(key, 0, sizeof *key);
    key->heap = heap;
    (void)devId;
    return 0;
}
int wc_falcon_init(falcon_key *key) { return wc_falcon_init_ex(key, NULL, INVALID_DEVID); }
int wc_falcon_set_level(falcon_key *key, byte level) {  /* level 1 is SNOVA; there is no level 5 */
    if (key == NULL || level != FALCON_LEVEL1) return BAD_FUNC_ARG;
    key->level = level;
    return 0;
}
int wc_falcon_get_level(falcon_key *key, byte *level) {
    if (key == NULL || level == NULL || key->level != FALCON_LEVEL1) return BAD_FUNC_ARG;
    *level = key->level;
    return 0;
}
void wc_falcon_free(falcon_key *key) {
    if (key != NULL) wc_ForceZero(key->k, sizeof key->k);
}
int wc_falcon_size(falcon_key *key) { return key ? FALCON_LEVEL1_KEY_SIZE : BAD_FUNC_ARG; }
int wc_falcon_priv_size(falcon_key *key) { return key ? FALCON_LEVEL1_PRV_KEY_SIZE : BAD_FUNC_ARG; }
int wc_falcon_pub_size(falcon_key *key) { return key ? FALCON_LEVEL1_PUB_KEY_SIZE : BAD_FUNC_ARG; }
int wc_falcon_sig_size(falcon_key *key) { return key ? FALCON_LEVEL1_SIG_SIZE : BAD_FUNC_ARG; }

int wc_falcon_import_public(const byte *in, word32 inLen, falcon_key *key) {
    if (in == NULL || key == NULL || key->level != FALCON_LEVEL1 || inLen != FALCON_LEVEL1_PUB_KEY_SIZE)
        return BAD_FUNC_ARG;
    XMEMCPY(key->p, in, inLen);
    key->pubKeySet = 1;
    return 0;
}
int wc_falcon_export_public(falcon_key *key, byte *out, word32 *outLen) {
    if (key == NULL || out == NULL || outLen == NULL || !key->pubKeySet) return BAD_FUNC_ARG;
    if (*outLen < FALCON_LEVEL1_PUB_KEY_SIZE) { *outLen = FALCON_LEVEL1_PUB_KEY_SIZE; return BUFFER_E; }
    XMEMCPY(out, key->p, FALCON_LEVEL1_PUB_KEY_SIZE);
    *outLen = FALCON_LEVEL1_PUB_KEY_SIZE;
    return 0;
}
/* the secret key, and the public key separately or after it (oqs-provider's sk || pk) */
int wc_falcon_import_private_key(const byte *priv, word32 privSz, const byte *pub, word32 pubSz, falcon_key *key) {
    if (priv == NULL || key == NULL || key->level != FALCON_LEVEL1) return BAD_FUNC_ARG;
    if (pub == NULL && privSz == FALCON_LEVEL1_PRV_KEY_SIZE) {
        pub = priv + FALCON_LEVEL1_KEY_SIZE;
        pubSz = FALCON_LEVEL1_PUB_KEY_SIZE;
        privSz = FALCON_LEVEL1_KEY_SIZE;
    }
    if (privSz != FALCON_LEVEL1_KEY_SIZE) return BAD_FUNC_ARG;
    if (pub != NULL && wc_falcon_import_public(pub, pubSz, key) != 0) return BAD_FUNC_ARG;
    XMEMCPY(key->k, priv, privSz);
    key->prvKeySet = 1;
    return 0;
}
int wc_falcon_import_private_only(const byte *priv, word32 privSz, falcon_key *key) {
    return wc_falcon_import_private_key(priv, privSz, NULL, 0, key);
}
int wc_falcon_check_key(falcon_key *key) {  /* ponytail: presence only; liboqs has no SNOVA pk-from-sk call */
    return key != NULL && key->pubKeySet && key->prvKeySet ? 0 : BAD_FUNC_ARG;
}

int wc_falcon_sign_msg(const byte *in, word32 inLen, byte *out, word32 *outLen, falcon_key *key, WC_RNG *rng) {
    size_t len = 0;
    int ret;
    if ((in == NULL && inLen) || out == NULL || outLen == NULL || key == NULL || rng == NULL || !key->prvKeySet)
        return BAD_FUNC_ARG;
    if (*outLen < FALCON_LEVEL1_SIG_SIZE) return BUFFER_E;
    sn_rng = rng;
    OQS_randombytes_custom_algorithm(sn_randombytes);
    wb_snova_sign_begin();
    ret = SN_SIGN(out, &len, in, inLen, key->k);
    wb_snova_sign_end();
    if (ret != OQS_SUCCESS) return BAD_STATE_E;
    *outLen = (word32)len;
    return 0;
}
int wc_falcon_verify_msg(const byte *sig, word32 sigLen, const byte *msg, word32 msgLen, int *res, falcon_key *key) {
    if (sig == NULL || (msg == NULL && msgLen) || res == NULL || key == NULL || !key->pubKeySet) return BAD_FUNC_ARG;
    *res = SN_VERIFY(msg, msgLen, sig, sigLen, key->p) == OQS_SUCCESS;
    return *res ? 0 : SIG_VERIFY_E;
}

/* the buffers on the heap, as falcon.c: up to 5.5 KB (level V), and key loading runs on the board's small stack */
int wc_Falcon_PrivateKeyDecode(const byte *input, word32 *inOutIdx, falcon_key *key, word32 inSz) {
    word32 privLen = FALCON_LEVEL1_PRV_KEY_SIZE, pubLen = FALCON_LEVEL1_PUB_KEY_SIZE;
    byte *priv, *pub;
    int ret;
    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0 || key->level != FALCON_LEVEL1)
        return BAD_FUNC_ARG;
    if ((priv = (byte *)XMALLOC(privLen + pubLen, key->heap, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) return MEMORY_E;
    pub = priv + privLen;
    ret = DecodeAsymKey(input, inOutIdx, inSz, priv, &privLen, pub, &pubLen, FALCON_LEVEL1k);
    if (ret == 0)
        ret = wc_falcon_import_private_key(priv, privLen, pubLen ? pub : NULL, pubLen, key);
    wc_ForceZero(priv, FALCON_LEVEL1_PRV_KEY_SIZE);
    XFREE(priv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
int wc_Falcon_PublicKeyDecode(const byte *input, word32 *inOutIdx, falcon_key *key, word32 inSz) {
    word32 pubLen = FALCON_LEVEL1_PUB_KEY_SIZE;
    byte *pub;
    int ret;
    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0) return BAD_FUNC_ARG;
    if (wc_falcon_import_public(input, inSz, key) == 0) return 0;  /* raw, as the certificate code passes it */
    if ((pub = (byte *)XMALLOC(pubLen, key->heap, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) return MEMORY_E;
    ret = DecodeAsymKeyPublic(input, inOutIdx, inSz, pub, &pubLen, FALCON_LEVEL1k);
    if (ret == 0) ret = wc_falcon_import_public(pub, pubLen, key);
    XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
int wc_Falcon_PublicKeyToDer(falcon_key *key, byte *output, word32 inLen, int withAlg) {
    if (key == NULL || !key->pubKeySet) return BAD_FUNC_ARG;
    return SetAsymKeyDerPublic(key->p, FALCON_LEVEL1_PUB_KEY_SIZE, output, inLen, FALCON_LEVEL1k, withAlg);
}
#endif
#endif /* HAVE_FALCON && WB_SNOVA */
