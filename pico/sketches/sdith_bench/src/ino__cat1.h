/* sdith_cat1_bench.ino, verbatim except include paths: "src/x" -> "x", "x" -> "../x" for files beside the sketch (this file lives in src/) */
// sdith_cat1_bench.ino - SDitH threshold cat1-gf256 (NIST round-2 onramp, MPC-in-the-head) on RP2040.
//   Source: signatures/SDitH Threshold_Variant ref (bundled Keccak), flattened in src/.
//   SDitH is HEAP-heavy: sign mallocs ~166 KB AND its stack peak (~9.4 KB) exceeds arduino-pico's
//   8 KB guard. So we run each op on a MODEST 32 KB SRAM stack (covers the 9.4 KB peak) and leave
//   the remaining ~200 KB of SRAM as heap for malloc. cat3/cat5 need 337/575 KB heap -> infeasible.
//   Build for the PLAIN Pico (rp2040:rp2040:rpipico). Serial @115200.

#include <Arduino.h>

#include <string.h>

extern "C" {
  #include "api.h"
  int randombytes(unsigned char *x, unsigned long long xlen);
}

extern "C" int randombytes(unsigned char *x, unsigned long long xlen) {
  while (xlen >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, 4); x += 4; xlen -= 4; }
  if (xlen) { uint32_t r = rp2040.hwrand32(); for (unsigned long long i = 0; i < xlen; i++) x[i] = (uint8_t)(r >> (8 * i)); }
  return 0;
}

#define BIG_STACK_BYTES (48u * 1024u)     // host sign ~10 KB; M0+ Keccak inflates frames. 48 KB is the
                                          // max we can give while leaving ~174 KB heap for the ~166 KB malloc.
#include "../bigstack.h"

#define ITERS 20
static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char sm[CRYPTO_BYTES + 32], m2[CRYPTO_BYTES + 32];
static unsigned char msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];
static unsigned long long g_smlen = 0, g_mlen2 = 0;
static uint32_t kpeak = 0, speak = 0, vpeak = 0;

static int th_keygen(void) { return crypto_sign_keypair(pk, sk); }
static int th_sign(void)   { return crypto_sign(sm, &g_smlen, msg, sizeof msg, sk); }
static int th_verify(void) { return crypto_sign_open(m2, &g_mlen2, sm, g_smlen, pk); }

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
  Serial.print("SDitH-thr-cat1-gf256  "); Serial.print(op);
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
    big_stack_paint(); uint32_t a0 = micros(); int rk = big_stack_run(th_keygen); uint32_t a1 = micros();
    tk[i] = a1 - a0; { uint32_t p = big_stack_peak(); if (p > kpeak) kpeak = p; }
    big_stack_paint(); uint32_t b0 = micros(); int rs = big_stack_run(th_sign);   uint32_t b1 = micros();
    ts[i] = b1 - b0; { uint32_t p = big_stack_peak(); if (p > speak) speak = p; }
    big_stack_paint(); uint32_t c0 = micros(); int r  = big_stack_run(th_verify); uint32_t c1 = micros();
    tv[i] = c1 - c0; { uint32_t p = big_stack_peak(); if (p > vpeak) vpeak = p; }
    (void)rk; (void)rs;
    if (r == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== SDitH threshold cat1-gf256 (ref, MPCitH) on RP2040 [big-stack] ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print((long)CRYPTO_PUBLICKEYBYTES);
  Serial.print(F(" sk=")); Serial.print((long)CRYPTO_SECRETKEYBYTES);
  Serial.print(F(" sigMax=")); Serial.print((long)CRYPTO_BYTES); Serial.print(F(" sig=")); Serial.println((long)(g_smlen - 32));
  report_op("keygen", tk, ITERS);
  report_op("sign",   ts, ITERS);
  report_op("verify", tv, ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
  Serial.print(F("big-stack peak used: keygen=")); Serial.print(kpeak);
  Serial.print(F(" sign=")); Serial.print(speak); Serial.print(F(" verify=")); Serial.print(vpeak);
  Serial.print(F(" / ")); Serial.print(BIG_STACK_BYTES); Serial.println(F(" bytes"));
  Serial.print(F("free heap: ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" bytes  (sign needs ~166 KB)"));
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
