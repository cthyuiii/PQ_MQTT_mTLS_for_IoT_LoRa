/* app_aead.h - message protection for mqtt_tls_timer's pipeline (MSGS > 0): the frames travel through
 * the MQTT broker. Every scheme protects the same LoRaWAN data frame, uplink (MHDR 0x40) or downlink (0x60):
 *   MHDR(1) | DevAddr(4) | FCtrl(1) | FCnt(2) | FPort(1) | payload | tag
 *   lorawan10  LoRaWAN 1.0.x: AES-128-CTR (A_i blocks) + AES-128-CMAC over B0|msg, 4-byte MIC
 *   lorawan11  LoRaWAN 1.1:   same encryption; uplink MIC = 2 bytes of each of two CMACs (two keys),
 *                             downlink MIC = 4 bytes of one CMAC (SNwkSIntKey)
 *   aes256ctr  the 1.0.x frame with 256-bit keys (AES-256-CTR + AES-256-CMAC, 4-byte MIC; LoRaWAN itself is AES-128
 *              only): the key-size comparison for LoRaWAN's CTR mode. CMAC key = nwk | nwk2
 *   lorawan11_256  the 1.1 frame with 256-bit keys: AES-256-CTR, and the 1.1 MIC rules with two AES-256-CMAC keys
 *              (F = nwk | nwk2, S = nwk2 | nwk: benchmark keys from the same material, same cost as independent ones)
 *   aes128gcm / aes256gcm     AES-GCM, header as AAD, nonce from DevAddr|FCnt|Dir, 16-byte tag
 *   aes128ccm / aes256ccm     AES-CCM (CTR + CBC-MAC, as BLE / 802.15.4), header as AAD, 13-byte nonce, 16-byte tag
 *   ascon      Ascon-AEAD128 (SP 800-232), header as AAD, nonce from DevAddr|FCnt|Dir, 16-byte tag
 *   none       header + plaintext (the unprotected reference)
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
/* tests only: fixed keys (app 32 B, nwk 16 B, nwk2 16 B) + DevAddr (4 B, wire order) */
void app_aead_set_keys(const unsigned char *app, const unsigned char *nwk, const unsigned char *nwk2,
                       const unsigned char *devaddr4);

#endif
