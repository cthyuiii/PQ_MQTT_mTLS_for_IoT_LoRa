// ed448_bench.ino - classical Ed448 (RFC 8032, pure mode) baseline on RP2040 / Pico (and RP2350).
//
//   Implementation: OpenSSL's self-contained Ed448-Goldilocks (crypto/ec/curve448/, Mike Hamburg
//   origin, Apache-2.0), flattened into src/. The OpenSSL EVP-SHAKE256 calls are redirected to
//   PQClean's fips202 (shake_shim.h); the few OpenSSL-isms (ossl_inline, __owur, constant_time.h,
//   crypto/ecx.h) are stubbed in ossl_compat.h / ecx_shim.h. Forced to the portable 32-bit field
//   path (no int128), so the host-verified code is identical to what runs on the M0+/M33.
//   Host-verified against the RFC 8032 7.4 Ed448 test vector (pubkey, signature, verify).
//
//   sk = seed(57)||public(57) = 114 B, pk = 57 B, signature = 114 B. Small working set: no
//   big-stack needed. Board: "Raspberry Pi Pico". Serial Monitor @115200.

#include <Arduino.h>
#include <string.h>

extern "C" {
  #include "src/api.h"
  int randombytes(unsigned char *x, unsigned long long xlen);
}

extern "C" int randombytes(unsigned char *x, unsigned long long xlen) {
  while (xlen >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, 4); x += 4; xlen -= 4; }
  if (xlen) { uint32_t r = rp2040.hwrand32(); for (unsigned long long i = 0; i < xlen; i++) x[i] = (uint8_t)(r >> (8 * i)); }
  return 0;
}

#define ITERS 20
static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char sm[CRYPTO_BYTES + 32], m2[CRYPTO_BYTES + 32];
static unsigned char msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];
static unsigned long long g_smlen = 0, g_mlen2 = 0;

static void report_op(const char *op, const uint32_t *t, int n) {
  uint32_t mn = 0xFFFFFFFFu, mx = 0; uint64_t sum = 0;
  static uint32_t srt[ITERS];
  for (int i = 0; i < n; i++) { uint32_t v = t[i]; srt[i] = v; sum += v; if (v < mn) mn = v; if (v > mx) mx = v; }
  for (int i = 1; i < n; i++) { uint32_t k = srt[i]; int j = i - 1; while (j >= 0 && srt[j] > k) { srt[j+1] = srt[j]; j--; } srt[j+1] = k; }
  uint32_t mean = (uint32_t)(sum / n);
  uint32_t median = (n & 1) ? srt[n/2] : (uint32_t)(((uint64_t)srt[n/2-1] + srt[n/2]) >> 1);
  uint64_t vsum = 0;
  for (int i = 0; i < n; i++) { int64_t d = (int64_t)t[i] - (int64_t)mean; vsum += (uint64_t)(d * d); }
  uint32_t sd = (uint32_t)sqrtf((float)(vsum / (n > 0 ? n : 1)));
  uint32_t mhz = F_CPU / 1000000u;
  float ops = (mean > 0) ? (1000000.0f / (float)mean) : 0.0f;
  Serial.print("Ed448  "); Serial.print(op);
  Serial.print(F("  n=")); Serial.print(n);
  Serial.print(F("  mean=")); Serial.print(mean); Serial.print(F("us/")); Serial.print(mean / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  median=")); Serial.print(median); Serial.print(F("us/")); Serial.print(median / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  std=")); Serial.print(sd); Serial.print(F("us/")); Serial.print(sd / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  min=")); Serial.print(mn); Serial.print(F("us  max=")); Serial.print(mx); Serial.print(F("us"));
  Serial.print(F("  mean_cyc=")); Serial.print((unsigned long)((uint64_t)mean * mhz));
  Serial.print(F("  median_cyc=")); Serial.print((unsigned long)((uint64_t)median * mhz));
  Serial.print(F("  ops/s=")); Serial.println(ops, 4); Serial.flush();
}

static void run_report() {
  Serial.print(F(">>> running, ITERS=")); Serial.println(ITERS); Serial.flush();
  int okv = 0;
  for (int i = 0; i < ITERS; i++) {
    msg[0] = (uint8_t)i;
    uint32_t a0 = micros(); int rk = crypto_sign_keypair(pk, sk); uint32_t a1 = micros();
    uint32_t b0 = micros(); int rs = crypto_sign(sm, &g_smlen, msg, sizeof msg, sk); uint32_t b1 = micros();
    uint32_t c0 = micros(); int r  = crypto_sign_open(m2, &g_mlen2, sm, g_smlen, pk); uint32_t c1 = micros();
    tk[i] = a1 - a0; ts[i] = b1 - b0; tv[i] = c1 - c0;
    (void)rk; (void)rs;
    if (r == 0 && g_mlen2 == sizeof msg && memcmp(m2, msg, sizeof msg) == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== Ed448 (RFC 8032 pure, OpenSSL Goldilocks + PQClean SHAKE) on RP2040 ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print((long)CRYPTO_PUBLICKEYBYTES);
  Serial.print(F(" sk=")); Serial.print((long)(CRYPTO_SECRETKEYBYTES - CRYPTO_PUBLICKEYBYTES));  // seed only (the API key appends pk)
  Serial.print(F(" sigMax=")); Serial.print((long)CRYPTO_BYTES); Serial.print(F(" sig=")); Serial.println((long)(g_smlen - 32));
  report_op("keygen", tk, ITERS);
  report_op("sign",   ts, ITERS);
  report_op("verify", tv, ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
  Serial.print(F("free stack: ")); Serial.print(rp2040.getFreeStack());
  Serial.print(F(" bytes   free heap: ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" bytes"));
  Serial.println(F("=== done (repeats in ~5s) ==="));
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  delay(200);
}

void loop() {
  run_report();
  delay(5000);
}
