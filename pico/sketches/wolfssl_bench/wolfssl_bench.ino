// wolfssl_bench.ino - wolfSSL / wolfCrypt 5.9.4 (an embedded-targeted library) as the alternative to
//   the PQClean / mldsa-native / NIST-reference / BearSSL sketches. Same report format, so
//   run_benchmarks.py files its rows in results.csv next to theirs ("<alg> (wolfSSL)").
//   One algorithm per build: the runner passes -DWB_<ALG> and wolfssl_user_settings.h compiles only
//   that algorithm in (the .uf2 size is its firmware cost). Big buffers live on the heap
//   (WOLFSSL_SMALL_STACK), so "peak heap" below is the scheme's RAM working set.
//   Library: pico/sketches/wolfssl_bench/make_wolfssl_lib.sh (same wolfSSL release as the Pi build).

#include <Arduino.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <string.h>

#if defined(__ARM_ARCH_6M__)
#define CHIP "RP2040"
#else
#define CHIP "RP2350"
#endif
#ifndef WB_ITERS
#define WB_ITERS 20
#endif

extern "C" int wb_rand_block(unsigned char *out, unsigned int n) {
  while (n >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(out, &r, 4); out += 4; n -= 4; }
  if (n) { uint32_t r = rp2040.hwrand32(); memcpy(out, &r, n); }
  return 0;
}

// ---- heap accounting through wolfSSL's allocator hooks (8-byte header keeps alignment) ----
static size_t cur_heap, peak_heap;
typedef union { size_t n; long long align; } hdr_t;
static void *wb_malloc(size_t n) {
  hdr_t *h = (hdr_t *)malloc(n + sizeof(hdr_t));
  if (!h) return NULL;
  h->n = n; cur_heap += n; if (cur_heap > peak_heap) peak_heap = cur_heap;
  return h + 1;
}
static void wb_free(void *p) {
  if (!p) return;
  hdr_t *h = (hdr_t *)p - 1; cur_heap -= h->n; free(h);
}
static void *wb_realloc(void *p, size_t n) {
  if (!p) return wb_malloc(n);
  hdr_t *h = (hdr_t *)p - 1; size_t old = h->n;
  hdr_t *nh = (hdr_t *)realloc(h, n + sizeof(hdr_t));
  if (!nh) return NULL;
  nh->n = n; cur_heap = cur_heap - old + n; if (cur_heap > peak_heap) peak_heap = cur_heap;
  return nh + 1;
}

static WC_RNG rng;
static byte msg[32];
static byte *sig;
static word32 sig_len, sig_max;
static int pk_len, sk_len;

// ---- one algorithm per build: LABEL + alg_init / alg_keygen / alg_sign / alg_verify ----
#if defined(WB_MLDSA44) || defined(WB_MLDSA65) || defined(WB_MLDSA87)
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#if defined(WB_MLDSA44)
#define LABEL "ML-DSA-44"
#define LEVEL WC_ML_DSA_44
#elif defined(WB_MLDSA65)
#define LABEL "ML-DSA-65"
#define LEVEL WC_ML_DSA_65
#else
#define LABEL "ML-DSA-87"
#define LEVEL WC_ML_DSA_87
#endif
static wc_MlDsaKey key;
static int alg_init() {
  int r = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
  if (!r) r = wc_MlDsaKey_SetParams(&key, LEVEL);
  int s = 0;
  if (!r) r = wc_MlDsaKey_GetSigLen(&key, &s);
  if (!r) r = wc_MlDsaKey_GetPubLen(&key, &pk_len);
  if (!r) r = wc_MlDsaKey_GetPrivLen(&key, &sk_len);
  sk_len -= pk_len;  // wolfSSL's private length includes the public key; report the private part, as the host bench
  sig_max = s;
  return r;
}
static int alg_keygen() { return wc_MlDsaKey_MakeKey(&key, &rng); }
static int alg_sign() { sig_len = sig_max; return wc_MlDsaKey_SignCtx(&key, NULL, 0, sig, &sig_len, msg, sizeof msg, &rng); }
static int alg_verify(int *ok) { return wc_MlDsaKey_VerifyCtx(&key, sig, sig_len, NULL, 0, msg, sizeof msg, ok); }

#elif defined(WB_SLHDSA_SHA2_128F) || defined(WB_SLHDSA_SHA2_128S) || \
      defined(WB_SLHDSA_SHAKE_128F) || defined(WB_SLHDSA_SHAKE_128S)
extern "C" {  // wolfSSL 5.9.2 and 5.9.4: wc_slhdsa.h has no extern "C" guard of its own
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
}
#if defined(WB_SLHDSA_SHA2_128F)
#define LABEL "SLH-DSA-SHA2-128f"
#define PARAM SLHDSA_SHA2_128F
#elif defined(WB_SLHDSA_SHA2_128S)
#define LABEL "SLH-DSA-SHA2-128s"
#define PARAM SLHDSA_SHA2_128S
#elif defined(WB_SLHDSA_SHAKE_128F)
#define LABEL "SLH-DSA-SHAKE-128f"
#define PARAM SLHDSA_SHAKE128F
#else
#define LABEL "SLH-DSA-SHAKE-128s"
#define PARAM SLHDSA_SHAKE128S
#endif
static SlhDsaKey key;
static int alg_init() {
  int r = wc_SlhDsaKey_Init(&key, PARAM, NULL, INVALID_DEVID);
  pk_len = wc_SlhDsaKey_PublicSizeFromParam(PARAM);
  sk_len = wc_SlhDsaKey_PrivateSizeFromParam(PARAM);
  sig_max = wc_SlhDsaKey_SigSizeFromParam(PARAM);
  return r;
}
static int alg_keygen() { return wc_SlhDsaKey_MakeKey(&key, &rng); }
static int alg_sign() { sig_len = sig_max; return wc_SlhDsaKey_Sign(&key, NULL, 0, msg, sizeof msg, sig, &sig_len, &rng); }
static int alg_verify(int *ok) { *ok = wc_SlhDsaKey_Verify(&key, NULL, 0, msg, sizeof msg, sig, sig_len) == 0; return 0; }

#elif defined(WB_ECDSA_P256)
#include <wolfssl/wolfcrypt/ecc.h>
#define LABEL "ECDSA-P256"
static ecc_key key;
static byte hash[WC_SHA256_DIGEST_SIZE];
static int alg_init() { pk_len = 64; sk_len = 32; sig_max = ECC_MAX_SIG_SIZE; return wc_ecc_init(&key); }
static int alg_keygen() {
  wc_ecc_free(&key); wc_ecc_init(&key);
  int r = wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
  return r ? r : wc_ecc_set_rng(&key, &rng);
}
static int alg_sign() {
  sig_len = sig_max;
  int r = wc_Sha256Hash(msg, sizeof msg, hash);
  return r ? r : wc_ecc_sign_hash(hash, sizeof hash, sig, &sig_len, &rng, &key);
}
static int alg_verify(int *ok) {
  int r = wc_Sha256Hash(msg, sizeof msg, hash);
  return r ? r : wc_ecc_verify_hash(sig, sig_len, hash, sizeof hash, ok, &key);
}

#elif defined(WB_ED25519)
#include <wolfssl/wolfcrypt/ed25519.h>
#define LABEL "Ed25519"
static ed25519_key key;
static int alg_init() { pk_len = ED25519_PUB_KEY_SIZE; sk_len = ED25519_KEY_SIZE;  /* seed only; ED25519_PRV_KEY_SIZE adds the public key */ sig_max = ED25519_SIG_SIZE; return wc_ed25519_init(&key); }
static int alg_keygen() { return wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key); }
static int alg_sign() { sig_len = sig_max; return wc_ed25519_sign_msg(msg, sizeof msg, sig, &sig_len, &key); }
static int alg_verify(int *ok) { return wc_ed25519_verify_msg(sig, sig_len, msg, sizeof msg, ok, &key); }

#elif defined(WB_RSA2048)
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#define LABEL "RSA-2048"
static RsaKey key;
static byte enc[64], dec[256];
static word32 enc_len;
static int alg_init() {
  pk_len = sk_len = 256; sig_max = 256;
  int r = wc_InitRsaKey(&key, NULL);
  byte h[WC_SHA256_DIGEST_SIZE];
  if (!r) r = wc_Sha256Hash(msg, sizeof msg, h);
  if (!r) { int n = wc_EncodeSignature(enc, h, sizeof h, SHA256h); if (n < 0) r = n; else enc_len = n; }
  return r;
}
static int alg_keygen() {
  wc_FreeRsaKey(&key); wc_InitRsaKey(&key, NULL);
  int r = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
  if (!r) { int d = wc_RsaKeyToDer(&key, NULL, 0); if (d > 0) sk_len = d; }  // PKCS#1 DER, as the host bench
  return r ? r : wc_RsaSetRNG(&key, &rng);
}
static int alg_sign() { int n = wc_RsaSSL_Sign(enc, enc_len, sig, sig_max, &key, &rng); sig_len = n > 0 ? n : 0; return n < 0 ? n : 0; }
static int alg_verify(int *ok) {
  int n = wc_RsaSSL_Verify(sig, sig_len, dec, sizeof dec, &key);
  *ok = n == (int)enc_len && memcmp(dec, enc, enc_len) == 0;
  return n < 0 ? n : 0;
}

#elif defined(WB_FALCON512) || defined(WB_FALCON1024)
#include <wolfssl/wolfcrypt/falcon.h>
#ifdef WB_FALCON512
#define LABEL "Falcon-512"
#define LEVEL 1
#else
#define LABEL "Falcon-1024"
#define LEVEL 5
#endif
static falcon_key key;
static int alg_init() {
  pk_len = LEVEL == 1 ? FALCON_LEVEL1_PUB_KEY_SIZE : FALCON_LEVEL5_PUB_KEY_SIZE;
  sk_len = LEVEL == 1 ? FALCON_LEVEL1_KEY_SIZE : FALCON_LEVEL5_KEY_SIZE;
  sig_max = LEVEL == 1 ? FALCON_LEVEL1_SIG_SIZE : FALCON_LEVEL5_SIG_SIZE;
  int r = wc_falcon_init(&key);
  return r ? r : wc_falcon_set_level(&key, LEVEL);
}
static int alg_keygen() { return wc_falcon_make_key(&key, &rng); }
static int alg_sign() { sig_len = sig_max; return wc_falcon_sign_msg(msg, sizeof msg, sig, &sig_len, &key, &rng); }
static int alg_verify(int *ok) { return wc_falcon_verify_msg(sig, sig_len, msg, sizeof msg, ok, &key); }

#else
#error "build with one -DWB_<ALG> (see run_benchmarks.py): MLDSA44/65/87, SLHDSA_SHA2_128F/S, SLHDSA_SHAKE_128F/S, ECDSA_P256, ED25519, RSA2048, FALCON512/1024"
#endif

static const char *lib_name() { static char v[32]; snprintf(v, sizeof v, "wolfSSL %s", LIBWOLFSSL_VERSION_STRING); return v; }

// ---- same statistics + line format as the other sketches ----
static uint32_t tk[WB_ITERS], ts[WB_ITERS], tv[WB_ITERS];
static size_t peak[3];

static void report_op(const char *op, const uint32_t *t, int n) {
  static uint32_t srt[WB_ITERS];
  uint32_t mn = 0xFFFFFFFFu, mx = 0; uint64_t sum = 0;
  for (int i = 0; i < n; i++) { srt[i] = t[i]; sum += t[i]; if (t[i] < mn) mn = t[i]; if (t[i] > mx) mx = t[i]; }
  for (int i = 1; i < n; i++) { uint32_t k = srt[i]; int j = i - 1; while (j >= 0 && srt[j] > k) { srt[j + 1] = srt[j]; j--; } srt[j + 1] = k; }
  uint32_t mean = (uint32_t)(sum / n);
  uint32_t median = (n & 1) ? srt[n / 2] : (uint32_t)(((uint64_t)srt[n / 2 - 1] + srt[n / 2]) >> 1);
  uint64_t vsum = 0;
  for (int i = 0; i < n; i++) { int64_t d = (int64_t)t[i] - (int64_t)mean; vsum += (uint64_t)(d * d); }
  uint32_t sd = (uint32_t)sqrtf((float)(vsum / n)), mhz = F_CPU / 1000000u;
  Serial.print(LABEL "(wolfSSL)  "); Serial.print(op);
  Serial.print(F("  n=")); Serial.print(n);
  Serial.print(F("  mean=")); Serial.print(mean); Serial.print(F("us/")); Serial.print(mean / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  median=")); Serial.print(median); Serial.print(F("us/")); Serial.print(median / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  std=")); Serial.print(sd); Serial.print(F("us/")); Serial.print(sd / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  min=")); Serial.print(mn); Serial.print(F("us  max=")); Serial.print(mx); Serial.print(F("us"));
  Serial.print(F("  mean_cyc=")); Serial.print((unsigned long)((uint64_t)mean * mhz));
  Serial.print(F("  median_cyc=")); Serial.print((unsigned long)((uint64_t)median * mhz));
  Serial.print(F("  ops/s=")); Serial.println(mean ? 1000000.0f / mean : 0.0f, 4); Serial.flush();
}

// time one op and track its peak heap; returns the wolfCrypt error code
static int timed(int (*fn)(), uint32_t *us, size_t *pk) {
  peak_heap = cur_heap; size_t base = cur_heap;
  uint32_t t0 = micros(); int r = fn(); *us = micros() - t0;
  if (peak_heap - base > *pk) *pk = peak_heap - base;
  return r;
}
static int do_verify_ok;
static int verify_thunk() { return alg_verify(&do_verify_ok); }

static void run_report() {
  Serial.print(F(">>> running, ITERS=")); Serial.println(WB_ITERS); Serial.flush();
  int okv = 0, sign_err = 0, r = alg_init();
  if (r) { Serial.print(F("!! init failed ")); Serial.println(r); return; }
  if (!sig) sig = (byte *)malloc(sig_max);  // app buffer: outside the wolfSSL heap accounting
  for (int i = 0; i < WB_ITERS; i++) {
    msg[0] = (uint8_t)i;
    if (!(r = timed(alg_keygen, &tk[i], &peak[0])))  // a failed signature is counted and signed again (Falcon:
      while ((r = timed(alg_sign, &ts[i], &peak[1])) && ++sign_err < 3 * WB_ITERS) {  // the TLS client's BUFFER_E)
        Serial.print(F("!! sign error ")); Serial.print(r); Serial.print(F(" at iter ")); Serial.println(i + 1);
      }
    if (r || (r = timed(verify_thunk, &tv[i], &peak[2]))) {
      Serial.print(F("!! wolfCrypt error ")); Serial.print(r); Serial.print(F(" at iter ")); Serial.println(i + 1);
      return;
    }
    if (do_verify_ok) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(WB_ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.print(F("=== " LABEL " (")); Serial.print(lib_name()); Serial.println(F(") on " CHIP " ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz"));
  Serial.print(F("sizes: pk=")); Serial.print(pk_len); Serial.print(F(" sk=")); Serial.print(sk_len);
  Serial.print(F(" sig=")); Serial.print(sig_len); Serial.print(F(" sigMax=")); Serial.println(sig_max);
  report_op("keygen", tk, WB_ITERS);
  report_op("sign", ts, WB_ITERS);
  report_op("verify", tv, WB_ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print('/'); Serial.println(WB_ITERS);
  Serial.print(F("sign errors (signed again): ")); Serial.println(sign_err);
  Serial.print(F("peak heap (wolfSSL allocations): keygen=")); Serial.print((unsigned)peak[0]);
  Serial.print(F(" sign=")); Serial.print((unsigned)peak[1]); Serial.print(F(" verify=")); Serial.print((unsigned)peak[2]);
  Serial.println(F(" bytes"));
  Serial.print(F("free stack: ")); Serial.print(rp2040.getFreeStack());
  Serial.print(F(" bytes   free heap: ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" bytes"));
  Serial.println(F("=== done (repeats in ~5s) ==="));
}


void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  delay(200);
  wolfSSL_SetAllocators(wb_malloc, wb_free, wb_realloc);
  wolfCrypt_Init();
  wc_InitRng(&rng);
}

void loop() {
  run_report();
  delay(5000);
}
