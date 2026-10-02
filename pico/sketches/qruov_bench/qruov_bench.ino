// qruov_bench.ino - QR-UOV round 3 (NIST additional signatures, spec v3.0, Aug 2026) on RP2040 / RP2350.
//   Source: the round 3 package's Reference_Implementation/ref, unchanged, except prim.h / prim.c: its OpenSSL
//   SHAKE layer is replaced by one on PQClean's FIPS202 (src/prim.*), and PRG = shake (-DPRG_IS_AES=0; the
//   package's default PRG is AES-128-CTR). Host-checked: the KAT files (100 entries) of all five level 1 sets are
//   byte-identical to the official reference's.
//   The runner picks the set: -DQRUOV_PARAM_1q127L3 (1q127L10, 1q31L3, 1q31L10, 1q7L10) and the big stack
//   (-DBIG_STACK_BYTES). Host stack peaks (keygen / sign / verify, KB): 1q127L3 27/25/21, 1q31L3 31/29/24,
//   1q127L10 56/59/51, 1q31L10 70/74/63, 1q7L10 114/122/102; heap ~0. Serial @115200.

#include <Arduino.h>
#include <string.h>

extern "C" {
  #include "src/api.h"  // CRYPTO_* and the set's QRUOV_* parameters
  void randombytes(unsigned char *x, unsigned long long xlen);
}

extern "C" void randombytes(unsigned char *x, unsigned long long xlen) {
  while (xlen >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, 4); x += 4; xlen -= 4; }
  if (xlen) { uint32_t r = rp2040.hwrand32(); for (unsigned long long i = 0; i < xlen; i++) x[i] = (uint8_t)(r >> (8 * i)); }
}

#ifndef BIG_STACK_BYTES   // the runner sets it per parameter set (host peak + margin)
  #define BIG_STACK_BYTES (128u * 1024u)
#endif
#include "bigstack.h"

#define ITERS 10
static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char sm[CRYPTO_BYTES + 32], m2[CRYPTO_BYTES + 32];
static unsigned char msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];
static unsigned long long g_smlen = 0, g_mlen2 = 0;
static uint32_t kpeak = 0, speak = 0, vpeak = 0;

static int th_keygen(void) { return crypto_sign_keypair(pk, sk); }
static int th_sign(void)   { return crypto_sign(sm, &g_smlen, msg, sizeof msg, sk); }
static int th_verify(void) { return crypto_sign_open(m2, &g_mlen2, sm, g_smlen, pk); }

static void print_label() {
  Serial.print("QR-UOV-q"); Serial.print(QRUOV_q); Serial.print('L'); Serial.print(QRUOV_L);
  Serial.print('v'); Serial.print(QRUOV_v); Serial.print('m'); Serial.print(QRUOV_m);
}

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
  print_label(); Serial.print("  "); Serial.print(op);
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
  Serial.print(F(">>> running ")); print_label(); Serial.print(F(", ITERS=")); Serial.println(ITERS); Serial.flush();
  int okv = 0;
  for (int i = 0; i < ITERS; i++) {
    msg[0] = (uint8_t)i;
    big_stack_paint(); uint32_t a0 = micros(); int rk = big_stack_run(th_keygen); uint32_t a1 = micros();
    tk[i] = a1 - a0; { uint32_t p = big_stack_peak(); if (p > kpeak) kpeak = p; }
    big_stack_paint(); uint32_t b0 = micros(); int rs = big_stack_run(th_sign); uint32_t b1 = micros();
    ts[i] = b1 - b0; { uint32_t p = big_stack_peak(); if (p > speak) speak = p; }
    big_stack_paint(); uint32_t c0 = micros(); int r = big_stack_run(th_verify); uint32_t c1 = micros();
    tv[i] = c1 - c0; { uint32_t p = big_stack_peak(); if (p > vpeak) vpeak = p; }
    (void)rk; (void)rs;
    if (r == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.print(F("=== ")); print_label(); Serial.println(F(" (QR-UOV round 3 ref, SHAKE PRG) on RP [big-stack] ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print((long)CRYPTO_PUBLICKEYBYTES);
  Serial.print(F(" sk=")); Serial.print((long)CRYPTO_SECRETKEYBYTES);
  Serial.print(F(" sigMax=")); Serial.print((long)CRYPTO_BYTES); Serial.print(F(" sig=")); Serial.println((long)(g_smlen - 32));
  report_op("keygen", tk, ITERS);
  report_op("sign",   ts, ITERS);
  report_op("verify", tv, ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
  Serial.print(F("big-stack peak: keygen=")); Serial.print(kpeak); Serial.print(F(" sign=")); Serial.print(speak);
  Serial.print(F(" verify=")); Serial.print(vpeak); Serial.print(F(" / ")); Serial.print(BIG_STACK_BYTES); Serial.println(F(" bytes"));
  Serial.print(F("free heap: ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" bytes"));
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
