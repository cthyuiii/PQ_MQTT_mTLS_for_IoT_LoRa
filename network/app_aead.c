/* app_aead.c - see app_aead.h. LoRaWAN layouts follow the LoRaWAN 1.0.x / 1.1 specifications
 * (FRMPayload encryption, 4.3.3; MIC, 4.4); app_aead_selftest() checks them against a published LoRaWAN
 * 1.0.x uplink (lora-packet README), a 1.1 downlink MIC (brocaar/lorawan), and CMAC against RFC 4493.
 * Data-frame crypto is identical in LoRaWAN 1.0.0-1.0.4. */
#include "app_aead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef HAVE_ASCON_C
#include "api.h"          /* ascon-c: CRYPTO_VERSION */
#include "crypto_aead.h"  /* ascon-c: crypto_aead_encrypt / decrypt */
#endif

enum { NONE, LW10, LW11, CTR256, GCM128, GCM256, CCM128, CCM256, ASCON };
const char *const APP_AEAD_NAMES[] = {"lorawan10", "lorawan11", "aes256ctr", "aes128gcm", "aes256gcm",
                                      "aes128ccm", "aes256ccm", "ascon", NULL};
static const char *const LABELS[] = {"none", "LoRaWAN-1.0.x AES-128-CTR+CMAC", "LoRaWAN-1.1 AES-128-CTR+2xCMAC",
                                     "AES-256-CTR+CMAC (LoRaWAN 1.0.x frame, 256-bit keys)", "AES-128-GCM", "AES-256-GCM",
                                     "AES-128-CCM", "AES-256-CCM", "Ascon-AEAD128"};
enum { CCM_N = 13 };  /* CCM nonce bytes (L = 2: payloads up to 64 KiB), as IEEE 802.15.4's CCM* */

static int kind = -1;
static unsigned char k_app[32], k_nwk[16], k_nwk2[16], devaddr[4] = {0x04, 0x03, 0x02, 0x01};
static EVP_CIPHER_CTX *ctr, *gcm, *ccm;
static EVP_MAC_CTX *cmac_f, *cmac_s;
static int is_ctr(void) { return kind == LW10 || kind == LW11 || kind == CTR256; }  /* LoRaWAN frame: CTR + 4-byte MIC */

static EVP_MAC_CTX *cmac_new(const unsigned char *key, int len) {
    EVP_MAC *m = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *c = EVP_MAC_CTX_new(m);
    OSSL_PARAM p[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, len == 32 ? "AES-256-CBC" : "AES-128-CBC", 0),
                      OSSL_PARAM_END};
    EVP_MAC_init(c, key, len, p);  /* key schedule once; per message EVP_MAC_init(c, NULL, ...) reuses it */
    EVP_MAC_free(m);
    return c;
}
static void cmac(EVP_MAC_CTX *c, const unsigned char b[16], const unsigned char *msg, int n, unsigned char out[16]) {
    size_t l;
    EVP_MAC_init(c, NULL, 0, NULL);
    EVP_MAC_update(c, b, 16);
    EVP_MAC_update(c, msg, n);
    EVP_MAC_final(c, out, &l, 16);
}

/* A_i (first = 0x01) / B0 (first = 0x49) block: first | 0^4 | Dir (0 up, 1 down) | DevAddr | FCnt(4 LE) | 0 | last */
static void block(unsigned char b[16], unsigned char first, int down, uint32_t fcnt, unsigned char last) {
    memset(b, 0, 16);
    b[0] = first;
    b[5] = (unsigned char)down;
    memcpy(b + 6, devaddr, 4);
    b[10] = fcnt; b[11] = fcnt >> 8; b[12] = fcnt >> 16; b[13] = fcnt >> 24;
    b[15] = last;
}
/* GCM / CCM / Ascon nonce: DevAddr | FCnt (all 32 bits) | Dir | zeros; GCM takes the first 12 bytes, CCM 13, Ascon 16. Unique
 * while a key never sees an FCnt twice per direction (uplink and downlink counters are separate in LoRaWAN, as Dir
 * is in A_i / B0). The frame carries FCnt's low 16 bits (as LoRaWAN does), so callers keep FCnt < 2^16 per key
 * here; a real receiver would reconstruct the upper half from its own counter. */
static void nonce(unsigned char n[16], int down, uint32_t fcnt) {
    memset(n, 0, 16);
    memcpy(n, devaddr, 4);
    n[4] = fcnt; n[5] = fcnt >> 8; n[6] = fcnt >> 16; n[7] = fcnt >> 24;
    n[8] = (unsigned char)down;
}

static void rebuild(void) {  /* (re)key every context from the current keys */
    EVP_CIPHER_CTX_free(ctr); EVP_CIPHER_CTX_free(gcm); EVP_CIPHER_CTX_free(ccm);
    EVP_MAC_CTX_free(cmac_f); EVP_MAC_CTX_free(cmac_s);
    ctr = gcm = ccm = NULL; cmac_f = cmac_s = NULL;
    if (is_ctr()) {
        ctr = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctr, kind == CTR256 ? EVP_aes_256_ctr() : EVP_aes_128_ctr(), NULL, k_app, NULL);
        if (kind == CTR256) {  /* 256-bit CMAC key = NwkSKey | the second network key (the frame has one MIC) */
            unsigned char k[32];
            memcpy(k, k_nwk, 16); memcpy(k + 16, k_nwk2, 16);
            cmac_f = cmac_new(k, 32);
        } else cmac_f = cmac_new(k_nwk, 16);
        if (kind == LW11) cmac_s = cmac_new(k_nwk2, 16);
    } else if (kind == GCM128 || kind == GCM256) {
        gcm = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(gcm, kind == GCM128 ? EVP_aes_128_gcm() : EVP_aes_256_gcm(), NULL, k_app, NULL, 1);
    } else if (kind == CCM128 || kind == CCM256) {  /* nonce and tag lengths before the key; per message only the IV */
        ccm = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ccm, kind == CCM128 ? EVP_aes_128_ccm() : EVP_aes_256_ccm(), NULL, NULL, NULL, 1);
        EVP_CIPHER_CTX_ctrl(ccm, EVP_CTRL_CCM_SET_IVLEN, CCM_N, NULL);
        EVP_CIPHER_CTX_ctrl(ccm, EVP_CTRL_CCM_SET_TAG, 16, NULL);
        EVP_CipherInit_ex(ccm, NULL, NULL, k_app, NULL, 1);
    }
}

int app_aead_init(const char *name) {
    kind = !strcmp(name, "none") ? NONE : -1;
    for (int i = 0; APP_AEAD_NAMES[i]; i++)
        if (!strcmp(name, APP_AEAD_NAMES[i])) kind = i + 1;
#ifndef HAVE_ASCON_C
    if (kind == ASCON) kind = -1;
#endif
    if (kind < 0) return -1;
    RAND_bytes(k_app, sizeof k_app); RAND_bytes(k_nwk, sizeof k_nwk); RAND_bytes(k_nwk2, sizeof k_nwk2);
    rebuild();
    return 0;
}
void app_aead_set_keys(const unsigned char *app, const unsigned char *nwk, const unsigned char *nwk2,
                       const unsigned char *d) {
    memcpy(k_app, app, 32); memcpy(k_nwk, nwk, 16); memcpy(k_nwk2, nwk2, 16); memcpy(devaddr, d, 4);
    rebuild();
}
const char *app_aead_label(void) { return kind >= 0 ? LABELS[kind] : "?"; }
const char *app_aead_library(void) {
#ifdef HAVE_ASCON_C
    if (kind == ASCON) return "ascon-c " CRYPTO_VERSION;
#endif
    return OpenSSL_version(OPENSSL_VERSION);
}
int app_aead_overhead(void) { return APP_HDR + (kind == NONE ? 0 : is_ctr() ? 4 : 16); }
int app_aead_max_payload(void) { return is_ctr() ? 255 - APP_HDR : kind == CCM128 || kind == CCM256 ? 65535 : 1 << 20; }

static void mic(const unsigned char *msg, int n, int down, uint32_t fcnt, unsigned char out[4]) {
    unsigned char b0[16], f[16], s[16];
    block(b0, 0x49, down, fcnt, (unsigned char)n);
    if (kind == LW11 && down) { cmac(cmac_s, b0, msg, n, s); memcpy(out, s, 4); return; }  /* 1.1 downlink: one CMAC,
        SNwkSIntKey, B0 with ConfFCnt = 0 (no ACK); 1.0.x downlinks are the same B0 under NwkSKey, below */
    cmac(cmac_f, b0, msg, n, f);
    if (kind != LW11) { memcpy(out, f, 4); return; }  /* 1.0.x, and the 256-bit-key variant of its frame */
    /* 1.1 uplink: B1 = 0x49 | ConfFCnt | TxDr | TxCh | Dir | DevAddr | FCnt | 0 | len; with ConfFCnt,
     * TxDr, TxCh = 0 its bytes equal B0, the second key is what differs. MIC = cmacS[0..1] | cmacF[0..1] */
    cmac(cmac_s, b0, msg, n, s);
    out[0] = s[0]; out[1] = s[1]; out[2] = f[0]; out[3] = f[1];
}

int app_seal(int down, uint32_t fcnt, const unsigned char *pt, int len, unsigned char *out) {
    unsigned char *ct = out + APP_HDR, iv[16];
    int n;
    out[0] = down ? 0x60 : 0x40;  /* MHDR: unconfirmed data up / down */ memcpy(out + 1, devaddr, 4); out[5] = 0; out[6] = fcnt; out[7] = fcnt >> 8; out[8] = 1;
    switch (kind) {
    case NONE:
        memcpy(ct, pt, len);
        return APP_HDR + len;
    case LW10: case LW11: case CTR256:
        if (len > app_aead_max_payload()) return -1;
        block(iv, 0x01, down, fcnt, 1);  /* A_1; CTR increments the last byte -> A_2, A_3, ... */
        EVP_EncryptInit_ex(ctr, NULL, NULL, NULL, iv);
        EVP_EncryptUpdate(ctr, ct, &n, pt, len);
        mic(out, APP_HDR + len, down, fcnt, ct + len);
        return APP_HDR + len + 4;
    case GCM128: case GCM256:
        nonce(iv, down, fcnt);
        EVP_CipherInit_ex(gcm, NULL, NULL, NULL, iv, 1);
        EVP_CipherUpdate(gcm, NULL, &n, out, APP_HDR);
        EVP_CipherUpdate(gcm, ct, &n, pt, len);
        EVP_CipherFinal_ex(gcm, ct + len, &n);
        EVP_CIPHER_CTX_ctrl(gcm, EVP_CTRL_GCM_GET_TAG, 16, ct + len);
        return APP_HDR + len + 16;
    case CCM128: case CCM256:
        if (len > app_aead_max_payload()) return -1;
        nonce(iv, down, fcnt);
        EVP_CipherInit_ex(ccm, NULL, NULL, NULL, iv, 1);
        EVP_CipherUpdate(ccm, NULL, &n, NULL, len);         /* CCM needs the payload length first */
        EVP_CipherUpdate(ccm, NULL, &n, out, APP_HDR);
        EVP_CipherUpdate(ccm, ct, &n, pt, len);
        EVP_CipherFinal_ex(ccm, ct + len, &n);
        EVP_CIPHER_CTX_ctrl(ccm, EVP_CTRL_CCM_GET_TAG, 16, ct + len);
        return APP_HDR + len + 16;
#ifdef HAVE_ASCON_C
    case ASCON: {
        unsigned long long cl;
        nonce(iv, down, fcnt);
        crypto_aead_encrypt(ct, &cl, pt, len, out, APP_HDR, NULL, iv, k_app);
        return APP_HDR + (int)cl;
    }
#endif
    }
    return -1;
}

int app_open(const unsigned char *in, int len, unsigned char *pt) {
    uint32_t fcnt = in[6] | in[7] << 8;  /* 16 bits on the wire, as in LoRaWAN */
    int down = in[0] >> 5 & 1;           /* MType 010 / 100 up, 011 / 101 down */
    memcpy(devaddr, in + 1, 4);          /* the frame's DevAddr, as a network server looks the session up */
    const unsigned char *ct = in + APP_HDR;
    int n, body = len - app_aead_overhead();
    unsigned char iv[16], m[4];
    if (body < 0) return -1;
    switch (kind) {
    case NONE:
        memcpy(pt, ct, body);
        return body;
    case LW10: case LW11: case CTR256:
        mic(in, len - 4, down, fcnt, m);
        if (CRYPTO_memcmp(m, in + len - 4, 4)) return -1;
        block(iv, 0x01, down, fcnt, 1);
        EVP_EncryptInit_ex(ctr, NULL, NULL, NULL, iv);
        EVP_EncryptUpdate(ctr, pt, &n, ct, body);
        return body;
    case GCM128: case GCM256:
        nonce(iv, down, fcnt);
        EVP_CipherInit_ex(gcm, NULL, NULL, NULL, iv, 0);
        EVP_CipherUpdate(gcm, NULL, &n, in, APP_HDR);
        EVP_CipherUpdate(gcm, pt, &n, ct, body);
        EVP_CIPHER_CTX_ctrl(gcm, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ct + body));
        return EVP_CipherFinal_ex(gcm, pt + body, &n) > 0 ? body : -1;
    case CCM128: case CCM256:
        nonce(iv, down, fcnt);
        EVP_CipherInit_ex(ccm, NULL, NULL, NULL, iv, 0);
        EVP_CIPHER_CTX_ctrl(ccm, EVP_CTRL_CCM_SET_TAG, 16, (void *)(ct + body));
        EVP_CipherUpdate(ccm, NULL, &n, NULL, body);
        EVP_CipherUpdate(ccm, NULL, &n, in, APP_HDR);
        return EVP_CipherUpdate(ccm, pt, &n, ct, body) > 0 ? body : -1;  /* CCM checks the tag here */
#ifdef HAVE_ASCON_C
    case ASCON: {
        unsigned long long ml;
        nonce(iv, down, fcnt);
        return crypto_aead_decrypt(pt, &ml, NULL, ct, len - APP_HDR, in, APP_HDR, iv, k_app) ? -1 : (int)ml;
    }
#endif
    }
    return -1;
}

static int unhex(const char *h, unsigned char *out) {
    int n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v; sscanf(h, "%2x", &v); out[n++] = (unsigned char)v;
    }
    return n;
}

int app_aead_selftest(void) {
    int saved = kind, bad = 0;
    unsigned char key[16], msg[64], t[16], want[64], buf[300], pt[300];
    /* 1. CMAC, RFC 4493 examples 1 and 2 (and the key reuse app_seal relies on) */
    unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
    EVP_MAC_CTX *c = cmac_new(key, 16);
    size_t l;
    EVP_MAC_init(c, NULL, 0, NULL); EVP_MAC_final(c, t, &l, 16);
    unhex("bb1d6929e95937287fa37d129b756746", want); bad |= memcmp(t, want, 16) != 0;
    unhex("6bc1bee22e409f96e93d7e117393172a", msg);
    EVP_MAC_init(c, NULL, 0, NULL); EVP_MAC_update(c, msg, 16); EVP_MAC_final(c, t, &l, 16);
    unhex("070a16b46b4d4144f79bdd9dd04a287c", want); bad |= memcmp(t, want, 16) != 0;
    EVP_MAC_CTX_free(c);
    /* 1b. CMAC with AES-256 (the aes256ctr MIC), NIST SP 800-38B example with Mlen = 128 */
    unsigned char k256[32];
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", k256);
    c = cmac_new(k256, 32);
    EVP_MAC_init(c, NULL, 0, NULL); EVP_MAC_update(c, msg, 16); EVP_MAC_final(c, t, &l, 16);
    unhex("28a7023f452e8f82bd4bf28d8c37c35c", want); bad |= memcmp(t, want, 16) != 0;
    EVP_MAC_CTX_free(c);
    /* 1c. AES-CCM, NIST SP 800-38C example 1 (7-byte nonce, 8-byte AAD, 4-byte tag) */
    {
        unsigned char n7[7], ad[8], p4[4], ct8[8]; int x;
        unhex("404142434445464748494a4b4c4d4e4f", key); unhex("10111213141516", n7); unhex("0001020304050607", ad);
        unhex("20212223", p4); unhex("7162015b4dac255d", want);
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e, EVP_aes_128_ccm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_CCM_SET_IVLEN, 7, NULL); EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_CCM_SET_TAG, 4, NULL);
        EVP_EncryptInit_ex(e, NULL, NULL, key, n7);
        EVP_EncryptUpdate(e, NULL, &x, NULL, 4); EVP_EncryptUpdate(e, NULL, &x, ad, 8); EVP_EncryptUpdate(e, ct8, &x, p4, 4);
        EVP_EncryptFinal_ex(e, ct8 + 4, &x); EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_CCM_GET_TAG, 4, ct8 + 4);
        bad |= memcmp(ct8, want, 8) != 0;
        EVP_CIPHER_CTX_free(e);
    }
    /* 2. LoRaWAN 1.0.x uplink from the lora-packet README: MIC + FRMPayload -> "test" */
    kind = LW10;
    unsigned char dev_saved[4]; memcpy(dev_saved, devaddr, 4);
    unhex("ec925802ae430ca77fd3dd73cb2cc588", k_app); unhex("44024241ed4ce9a68c6a8bc055233fd3", k_nwk);
    unhex("f17dbe49", devaddr);
    rebuild();
    int fl = unhex("40F17DBE4900020001954378762B11FF0D", buf);
    bad |= app_open(buf, fl, pt) != 4 || memcmp(pt, "test", 4) != 0;
    bad |= app_seal(0, 2, (const unsigned char *)"test", 4, pt) != fl || memcmp(pt, buf, fl) != 0;
    /* 2b. LoRaWAN 1.1 downlink MIC from ChirpStack's lorawan library (phypayload_test.go, "Mac-commands in FOpts
     * (encrypted, using AFCntDown encryption flag)"): CMAC under SNwkSIntKey over B0 with Dir = 1 */
    kind = LW11;
    memset(k_nwk2, 2, 16); unhex("04030201", devaddr);
    rebuild();
    fl = unhex("600403020103000002070101" "77701ea3", buf);
    mic(buf, fl - 4, 1, 0, t);
    bad |= memcmp(t, buf + fl - 4, 4) != 0;
    memcpy(devaddr, dev_saved, 4);
    /* 3. round trip + tamper rejection for every scheme and direction (incl. a multi-block 222 B payload); an
     * uplink and a downlink with the same FCnt must not share a keystream / nonce */
    unsigned char src[222], up[300];
    for (int i = 0; i < 222; i++) src[i] = (unsigned char)i;
    for (int k = 0; APP_AEAD_NAMES[k]; k++) {
        if (app_aead_init(APP_AEAD_NAMES[k])) continue;  /* Ascon not built in */
        for (int down = 0; down < 2; down++) {
            int n = app_seal(down, 7, src, 222, buf);
            bad |= n != 222 + app_aead_overhead();
            bad |= app_open(buf, n, pt) != 222 || memcmp(pt, src, 222) != 0;
            buf[APP_HDR + 3] ^= 1; bad |= app_open(buf, n, pt) != -1; buf[APP_HDR + 3] ^= 1;
            buf[n - 1] ^= 1;       bad |= app_open(buf, n, pt) != -1;
            if (down) bad |= memcmp(up + APP_HDR, buf + APP_HDR, 222) == 0;
            else memcpy(up, buf, n);
        }
    }
    if (saved == NONE) app_aead_init("none");
    else if (saved > 0) app_aead_init(APP_AEAD_NAMES[saved - 1]);
    else kind = -1;
    return bad;
}
