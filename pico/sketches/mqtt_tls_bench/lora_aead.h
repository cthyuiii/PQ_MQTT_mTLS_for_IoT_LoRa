// lora_aead.h - the Pico's payload protection for mqtt_tls_bench's pipeline: the same LoRaWAN data frame, schemes
// and bytes as network/app_aead.c (checked byte for byte by pico/tests/aead_host_test), so a frame sealed
// here travels through the MQTT broker exactly like the host's.
//   MHDR(1) | DevAddr(4) | FCtrl(1) | FCnt(2) | FPort(1) | payload | MIC (4) or tag (16); MHDR 0x40 up, 0x60 down
//   none       header + plaintext (the unprotected reference)
//   lorawan10  LoRaWAN 1.0.x: AES-128-CTR (A_i blocks) + AES-128-CMAC over B0 | frame, 4-byte MIC
//   lorawan11  LoRaWAN 1.1: same encryption; uplink MIC from two CMACs (two keys), downlink MIC from one (SNwkSIntKey)
//   aes256ctr  the 1.0.x frame with 256-bit keys (AES-256-CTR + AES-256-CMAC; CMAC key = k_nwk | k_nwk2)
//   aes128gcm / aes256gcm, aes128ccm / aes256ccm, ascon: header as AAD, nonce DevAddr | FCnt (32 bits) | Dir | zeros
//              (GCM 12 bytes, CCM 13, Ascon 16), 16-byte tag
// AES: BearSSL bundled in arduino-pico (constant-time aes_ct; neither chip has an AES engine). BearSSL has no CMAC,
// so CMAC is built on its AES-CBC (RFC 4493). Ascon: official ascon-c 'armv6m_lowsize' (Cortex-M0 assembly,
// NIST SP 800-232), in src/. la_kat() checks CMAC (128 / 256), CCM, LoRaWAN and Ascon against published vectors
// before any message is sent.
// Header-only on purpose: the sketch and the host test both include it.
#pragma once
#include <bearssl/bearssl.h>
#include <stdio.h>
#include <string.h>

extern "C" {
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m,
                        unsigned long long mlen, const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub, const unsigned char *k);
}

enum { HDR = 9, MAXP = 222, TAG = 16, CCM_N = 13 };
static uint8_t k_app[32], k_nwk[16], k_nwk2[16], devaddr[4] = {0x04, 0x03, 0x02, 0x01};
static uint8_t pt[MAXP], frame[HDR + MAXP + TAG], out[MAXP];
static uint32_t fcnt;  // the device's frame counter: runs on across schemes and connections (a key never sees an
static bool down;      // FCnt twice per direction: keep a run under 65,536 frames); down = downlink frames
struct cmac_key { br_aes_ct_cbcenc_keys aes; uint8_t k1[16], k2[16]; };
typedef int (*la_fn)(int len);

// the frame's direction, from its MHDR (MType 010 up, 011 down): seal writes it first, open reads it
static uint8_t dir() { return frame[0] >> 5 & 1; }
// ---- LoRaWAN blocks: A_i (0x01) / B0 (0x49) = first | 0^4 | Dir | DevAddr | FCnt(4 LE) | 0 | last
static void block(uint8_t b[16], uint8_t first, uint32_t fc, uint8_t last) {
  memset(b, 0, 16);
  b[0] = first; b[5] = dir(); memcpy(b + 6, devaddr, 4);
  b[10] = fc; b[11] = fc >> 8; b[12] = fc >> 16; b[13] = fc >> 24; b[15] = last;
}
// GCM / CCM / Ascon nonce, as app_aead.c: DevAddr | FCnt (32 bits) | Dir | zeros; GCM uses 12 bytes, CCM 13, Ascon 16
static void nonce(uint8_t n[16], uint32_t fc) {
  memset(n, 0, 16); memcpy(n, devaddr, 4);
  n[4] = fc; n[5] = fc >> 8; n[6] = fc >> 16; n[7] = fc >> 24; n[8] = dir();
}
static void header(uint32_t fc) {
  frame[0] = down ? 0x60 : 0x40; memcpy(frame + 1, devaddr, 4); frame[5] = 0; frame[6] = fc; frame[7] = fc >> 8; frame[8] = 1;
}

// ---- AES-CMAC (RFC 4493) on BearSSL's constant-time AES-CBC: CBC-MAC with subkeys K1/K2
static cmac_key cm_f, cm_s;
static void dbl(uint8_t o[16], const uint8_t in[16]) {
  uint8_t carry = in[0] >> 7;
  for (int i = 0; i < 15; i++) o[i] = (in[i] << 1) | (in[i + 1] >> 7);
  o[15] = (in[15] << 1) ^ (carry ? 0x87 : 0);
}
static void cmac_init(cmac_key *c, const uint8_t *key, int klen = 16) {  // klen 16 or 32 (AES-128 / AES-256)
  uint8_t l[16] = {0}, iv[16] = {0};
  br_aes_ct_cbcenc_init(&c->aes, key, klen);
  br_aes_ct_cbcenc_run(&c->aes, iv, l, 16);  // L = AES(K, 0^128)
  dbl(c->k1, l); dbl(c->k2, c->k1);
}
static void cmac(const cmac_key *c, const uint8_t b0[16], const uint8_t *msg, int n, uint8_t t[16]) {
  static uint8_t buf[16 + HDR + MAXP + 32];
  int total = (b0 ? 16 : 0) + n, blocks = total ? (total + 15) / 16 : 1;
  if (b0) memcpy(buf, b0, 16);
  memcpy(buf + (b0 ? 16 : 0), msg, n);
  uint8_t *last = buf + (blocks - 1) * 16;
  bool full = total && total % 16 == 0;
  if (!full) { buf[total] = 0x80; memset(buf + total + 1, 0, blocks * 16 - total - 1); }
  for (int i = 0; i < 16; i++) last[i] ^= full ? c->k1[i] : c->k2[i];
  uint8_t iv[16] = {0};
  br_aes_ct_cbcenc_run(&c->aes, iv, buf, blocks * 16);
  memcpy(t, last, 16);
}

// ---- schemes: seal(len) protects pt into frame; open(len) verifies + decrypts frame into out (0 = ok)
static br_aes_ct_ctr_keys lw_ctr, gcm_aes;
static br_gcm_context gcm;
static br_aes_ct_ctrcbc_keys ccm_aes;
static br_ccm_context ccm;
static bool lw11;

static void mic(int n, uint32_t fc, uint8_t m[4]) {  // over frame[0..n)
  uint8_t b0[16], f[16], s[16];
  block(b0, 0x49, fc, (uint8_t)n);
  if (lw11 && dir()) { cmac(&cm_s, b0, frame, n, s); memcpy(m, s, 4); return; }  // 1.1 downlink: SNwkSIntKey only
  cmac(&cm_f, b0, frame, n, f);
  if (!lw11) { memcpy(m, f, 4); return; }
  cmac(&cm_s, b0, frame, n, s);  // 1.1: B1 == B0 bytes when ConfFCnt/TxDr/TxCh = 0; second key
  m[0] = s[0]; m[1] = s[1]; m[2] = f[0]; m[3] = f[1];
}
static void lw_crypt(uint32_t fc, uint8_t *data, int len) {  // CTR with A_1, A_2, ... (counter in byte 15)
  uint8_t a[16];
  block(a, 0x01, fc, 1);
  br_aes_ct_ctr_run(&lw_ctr, a, (uint32_t)a[12] << 24 | (uint32_t)a[13] << 16 | a[14] << 8 | a[15], data, len);
}
static int none_seal(int len) { header(++fcnt & 0xFFFF); memcpy(frame + HDR, pt, len); return 0; }
static int none_open(int len) { memcpy(out, frame + HDR, len); return 0; }
static int lw_seal(int len) {
  header(++fcnt & 0xFFFF);
  memcpy(frame + HDR, pt, len); lw_crypt(fcnt & 0xFFFF, frame + HDR, len);
  mic(HDR + len, fcnt & 0xFFFF, frame + HDR + len);
  return 0;
}
static int lw_open(int len) {
  uint32_t fc = frame[6] | frame[7] << 8;
  uint8_t m[4];
  mic(HDR + len, fc, m);
  if (memcmp(m, frame + HDR + len, 4)) return -1;
  memcpy(out, frame + HDR, len); lw_crypt(fc, out, len);
  return 0;
}
static int gcm_seal(int len) {
  uint8_t n[16];
  header(++fcnt & 0xFFFF); nonce(n, fcnt & 0xFFFF);
  br_gcm_reset(&gcm, n, 12); br_gcm_aad_inject(&gcm, frame, HDR); br_gcm_flip(&gcm);
  memcpy(frame + HDR, pt, len); br_gcm_run(&gcm, 1, frame + HDR, len); br_gcm_get_tag(&gcm, frame + HDR + len);
  return 0;
}
static int gcm_open(int len) {
  uint8_t n[16];
  nonce(n, frame[6] | frame[7] << 8);
  br_gcm_reset(&gcm, n, 12); br_gcm_aad_inject(&gcm, frame, HDR); br_gcm_flip(&gcm);
  memcpy(out, frame + HDR, len); br_gcm_run(&gcm, 0, out, len);
  return br_gcm_check_tag(&gcm, frame + HDR + len) ? 0 : -1;
}
static int ccm_seal(int len) {
  uint8_t n[16];
  header(++fcnt & 0xFFFF); nonce(n, fcnt & 0xFFFF);
  br_ccm_reset(&ccm, n, CCM_N, HDR, len, TAG); br_ccm_aad_inject(&ccm, frame, HDR); br_ccm_flip(&ccm);
  memcpy(frame + HDR, pt, len); br_ccm_run(&ccm, 1, frame + HDR, len); br_ccm_get_tag(&ccm, frame + HDR + len);
  return 0;
}
static int ccm_open(int len) {
  uint8_t n[16];
  nonce(n, frame[6] | frame[7] << 8);
  br_ccm_reset(&ccm, n, CCM_N, HDR, len, TAG); br_ccm_aad_inject(&ccm, frame, HDR); br_ccm_flip(&ccm);
  memcpy(out, frame + HDR, len); br_ccm_run(&ccm, 0, out, len);
  return br_ccm_check_tag(&ccm, frame + HDR + len) ? 0 : -1;
}
static int ascon_seal(int len) {
  uint8_t n[16]; unsigned long long cl;
  header(++fcnt & 0xFFFF); nonce(n, fcnt & 0xFFFF);
  return crypto_aead_encrypt(frame + HDR, &cl, pt, len, frame, HDR, NULL, n, k_app);
}
static int ascon_open(int len) {
  uint8_t n[16]; unsigned long long ml;
  nonce(n, frame[6] | frame[7] << 8);
  return crypto_aead_decrypt(out, &ml, NULL, frame + HDR, len + TAG, frame, HDR, n, k_app);
}

// the pipeline's schemes, named as the host's --aeads (app_aead.c)
struct la_scheme { const char *name, *label, *lib; la_fn seal, open; int tag; };
static const la_scheme LA[] = {
  {"none", "none", "-", none_seal, none_open, 0},
  {"lorawan10", "LoRaWAN-1.0.x AES-128-CTR+CMAC", "BearSSL (arduino-pico)", lw_seal, lw_open, 4},
  {"lorawan11", "LoRaWAN-1.1 AES-128-CTR+2xCMAC", "BearSSL (arduino-pico)", lw_seal, lw_open, 4},
  {"aes256ctr", "AES-256-CTR+CMAC (LoRaWAN 1.0.x frame, 256-bit keys)", "BearSSL (arduino-pico)", lw_seal, lw_open, 4},
  {"aes128gcm", "AES-128-GCM", "BearSSL (arduino-pico)", gcm_seal, gcm_open, TAG},
  {"aes256gcm", "AES-256-GCM", "BearSSL (arduino-pico)", gcm_seal, gcm_open, TAG},
  {"aes128ccm", "AES-128-CCM", "BearSSL (arduino-pico)", ccm_seal, ccm_open, TAG},
  {"aes256ccm", "AES-256-CCM", "BearSSL (arduino-pico)", ccm_seal, ccm_open, TAG},
  {"ascon", "Ascon-AEAD128", "ascon-c armv6m_lowsize", ascon_seal, ascon_open, TAG}};
enum { LA_N = sizeof LA / sizeof *LA };
// key schedules for scheme k from the current keys (k_app, k_nwk, k_nwk2); the "256" schemes use 256-bit keys
static void la_setup(int k) {
  int kl = strstr(LA[k].name, "256") ? 32 : 16;
  uint8_t nk[32];
  memcpy(nk, k_nwk, 16); memcpy(nk + 16, k_nwk2, 16);  // aes256ctr's CMAC key, as app_aead.c
  lw11 = !strcmp(LA[k].name, "lorawan11");
  br_aes_ct_ctr_init(&lw_ctr, k_app, kl); cmac_init(&cm_f, kl == 32 ? nk : k_nwk, kl); cmac_init(&cm_s, k_nwk2);
  br_aes_ct_ctr_init(&gcm_aes, k_app, kl); br_gcm_init(&gcm, &gcm_aes.vtable, br_ghash_ctmul32);
  br_aes_ct_ctrcbc_init(&ccm_aes, k_app, kl); br_ccm_init(&ccm, &ccm_aes.vtable);
}

// ---- known-answer checks (run on the board before any message)
static void unhex(const char *h, uint8_t *o) { for (; h[0] && h[1]; h += 2) { unsigned v; sscanf(h, "%2x", &v); *o++ = v; } }
static bool cmac_kat() {  // RFC 4493 example 2
  uint8_t key[16], m[16], want[16], t[16]; cmac_key c;
  unhex("2b7e151628aed2a6abf7158809cf4f3c", key); unhex("6bc1bee22e409f96e93d7e117393172a", m);
  unhex("070a16b46b4d4144f79bdd9dd04a287c", want);
  cmac_init(&c, key); cmac(&c, NULL, m, 16, t);
  return memcmp(t, want, 16) == 0;
}
static bool cmac256_kat() {  // NIST SP 800-38B, AES-256, Mlen = 128
  uint8_t key[32], m[16], want[16], t[16]; cmac_key c;
  unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
  unhex("6bc1bee22e409f96e93d7e117393172a", m); unhex("28a7023f452e8f82bd4bf28d8c37c35c", want);
  cmac_init(&c, key, 32); cmac(&c, NULL, m, 16, t);
  return memcmp(t, want, 16) == 0;
}
static bool ccm_kat() {  // NIST SP 800-38C example 1: 7-byte nonce, 8-byte AAD, 4-byte payload and tag
  uint8_t key[16], n[7], ad[8], d[4], want[8], tag[4];
  unhex("404142434445464748494a4b4c4d4e4f", key); unhex("10111213141516", n); unhex("0001020304050607", ad);
  unhex("20212223", d); unhex("7162015b4dac255d", want);
  br_aes_ct_ctrcbc_keys k; br_ccm_context c;
  br_aes_ct_ctrcbc_init(&k, key, 16); br_ccm_init(&c, &k.vtable);
  br_ccm_reset(&c, n, 7, 8, 4, 4); br_ccm_aad_inject(&c, ad, 8); br_ccm_flip(&c);
  br_ccm_run(&c, 1, d, 4); br_ccm_get_tag(&c, tag);
  return memcmp(d, want, 4) == 0 && memcmp(tag, want + 4, 4) == 0;
}
static bool lorawan_kat() {  // lora-packet README uplink 40F17DBE4900020001954378762B11FF0D + a 1.1 downlink MIC
  uint8_t d0[4]; memcpy(d0, devaddr, 4);
  unhex("f17dbe49", devaddr); unhex("ec925802ae430ca77fd3dd73cb2cc588", k_app);
  unhex("44024241ed4ce9a68c6a8bc055233fd3", k_nwk);
  br_aes_ct_ctr_init(&lw_ctr, k_app, 16); cmac_init(&cm_f, k_nwk); lw11 = false;
  unhex("40F17DBE4900020001954378762B11FF0D", frame);
  bool ok = lw_open(4) == 0 && memcmp(out, "test", 4) == 0;
  // LoRaWAN 1.1 downlink MIC (ChirpStack lorawan phypayload_test.go): one CMAC under SNwkSIntKey, Dir = 1 in B0
  uint8_t k2[16], m[4];
  memset(k2, 2, 16); cmac_init(&cm_s, k2); unhex("04030201", devaddr); lw11 = true;
  unhex("600403020103000002070101", frame);
  mic(12, 0, m);
  ok = ok && memcmp(m, "\x77\x70\x1e\xa3", 4) == 0;
  lw11 = false;
  memcpy(devaddr, d0, 4);
  return ok;
}
static bool ascon_kat() {  // ascon-c LWC_AEAD_KAT_128_128.txt Count 35
  static const uint8_t want[] = {0x96, 0x2B, 0x80, 0x16, 0x83, 0x6C, 0x75, 0xA7, 0xD8,
                                 0x68, 0x66, 0x58, 0x8C, 0xA2, 0x45, 0xD8, 0x86};
  uint8_t k[16], n[16], m = 0x20, ad = 0x30, c[sizeof want];
  unsigned long long clen;
  for (int i = 0; i < 16; i++) { k[i] = i; n[i] = 16 + i; }
  crypto_aead_encrypt(c, &clen, &m, 1, &ad, 1, NULL, n, k);
  return clen == sizeof want && memcmp(c, want, sizeof want) == 0;
}
// all of them; they overwrite the keys, so call before setting the session keys
static bool la_kat() { return cmac_kat() && cmac256_kat() && ccm_kat() && lorawan_kat() && ascon_kat(); }
