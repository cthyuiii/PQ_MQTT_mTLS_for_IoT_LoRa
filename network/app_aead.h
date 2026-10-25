/* app_aead.h - message protection for mqtt_tls_timer's pipeline (MSGS > 0): the frames travel through
 * the MQTT broker. Every scheme protects the same LoRaWAN data frame, uplink (MHDR 0x40) or downlink (0x60):
 *   MHDR(1) | DevAddr(4) | FCtrl(1) | FCnt(2) | FPort(1) | payload | tag
 *   lorawan10  LoRaWAN 1.0.x: AES-128-CTR (A_i blocks) + AES-128-CMAC over B0|msg, 4-byte MIC
 *   lorawan11  LoRaWAN 1.1:   same encryption; uplink MIC = 2 bytes of each of two CMACs (two keys),
 *                             downlink MIC = 4 bytes of one CMAC (SNwkSIntKey)
 *   aes256ctr  LoRaWAN 1.0.x with AES-256 (our ChirpStack, docs/aes256_lorawan.md): AES-256-CTR + AES-256-CMAC,
 *              4-byte MIC; AppSKey = the app key, NwkSKey = the first network key
 *   lorawan11_256  LoRaWAN 1.1 with AES-256: AES-256-CTR, and the 1.1 MIC rules with two AES-256-CMAC keys
 *              (FNwkSIntKey = the first network key, SNwkSIntKey = the second)
 *   aes128gcm / aes256gcm     AES-GCM, header as AAD, nonce from DevAddr|FCnt|Dir, 16-byte tag
 *   aes128ccm / aes256ccm     AES-CCM (CTR + CBC-MAC, as BLE / 802.15.4), header as AAD, 13-byte nonce, 16-byte tag
 *   ascon      Ascon-AEAD128 (SP 800-232), header as AAD, nonce from DevAddr|FCnt|Dir, 16-byte tag
 *   none       header + plaintext (the unprotected reference)
 *   lorawan11_e2e  a lorawan11_256 frame (FPort 2) around AES-256-CTR (the same A_i blocks) + a 4-byte
 *              AES-256-CMAC tag over B0 | that ciphertext, under a separate 256-bit key (the tag's key derived from it):
 *              a LoRaWAN network server (ChirpStack) checks the MIC and removes the outer layer with the keys it holds;
 *              only the application, holding the e2e key, checks the tag and reads the payload. Overhead 8 B: a
 *              47-byte reading fits DR0's 51-byte FRMPayload
 * FPort is 1, and 2 for lorawan11_e2e (app_open checks it: the same keys open both, FPort says which). Keys are 32 B;
 * the AES-128 frames (lorawan10, lorawan11, aes128gcm / ccm: benchmarks only, our ChirpStack refuses them) use each
 * key's first 16 bytes. app_open also opens frames with FOpts (the MAC commands stay as they are: 1.1 encrypts them
 * under NwkSEncKey, which this code doesn't hold).
 * OpenSSL libcrypto for AES/CMAC; ascon-c compiled in when HAVE_ASCON_C is defined.
 */
#ifndef APP_AEAD_H
#define APP_AEAD_H
#include <stdint.h>

#define APP_HDR 9
extern const char *const APP_AEAD_NAMES[];   /* NULL-terminated, "none" excluded */

int app_aead_init(const char *name);       /* 0 = ok, -1 = unknown / not built in */
const char *app_aead_label(void);          /* e.g. "LoRaWAN-1.0 AES-128-CTR+CMAC" */
const char *app_aead_library(void);        /* e.g. "OpenSSL 3.5.1" or "ascon-c 1.3.0" */
int app_aead_overhead(void);               /* bytes added to a payload on the wire */
int app_aead_max_payload(void);            /* LoRaWAN's B0 length byte caps msg at 255 B */
/* down = 0 uplink (device -> network), 1 downlink; -> frame length */
int app_seal(int down, uint32_t fcnt, const unsigned char *pt, int len, unsigned char *out);
int app_open(const unsigned char *in, int len, unsigned char *pt);  /* direction from MHDR; -> payload length, -1 = rejected */
int app_aead_selftest(void);               /* 0 = all known-answer + tamper checks pass */
/* fixed keys (app, nwk, nwk2: 32 B each) + DevAddr (4 B, wire order) */
void app_aead_set_keys(const unsigned char *app, const unsigned char *nwk, const unsigned char *nwk2,
                       const unsigned char *devaddr4);
void app_aead_set_e2e_key(const unsigned char *e2e32);  /* lorawan11_e2e's inner key (32 B) */

/* OTAA with AES-256 (docs/aes256_lorawan.md, "Joins" and "Key derivation"). root = AppKey (1.0.x) or NwkKey (1.1);
 * EUIs in wire order (little-endian). The join-request's bytes are the same in both versions. -> 23, its length */
int app_join_request(const unsigned char root[32], const unsigned char join_eui[8], const unsigned char dev_eui[8],
                     uint16_t dev_nonce, unsigned char out[23]);
/* decrypts and checks a join-accept (17 or 33 B) for that join-request; v11 = 1 for 1.1 (app_key = its AppKey), 0 for
 * 1.0.x (app_key unused). On success: keys = AppSKey | FNwkSIntKey | SNwkSIntKey (1.0.x: AppSKey | NwkSKey | NwkSKey),
 * 96 B, and the DevAddr (wire order). -> 0; -1 = not a join-accept for these keys (or its MIC fails); -2 = its OptNeg
 * bit says the other version (ChirpStack's device profile doesn't match) */
int app_join_accept(int v11, const unsigned char *in, int len, const unsigned char root[32], const unsigned char *app_key,
                    const unsigned char join_eui[8], const unsigned char dev_eui[8], uint16_t dev_nonce,
                    unsigned char keys[96], unsigned char devaddr4[4]);

#endif
