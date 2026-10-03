// sqisign_bench.ino - SQIsign round 3 (isogenies; the-sqisign "third-round version") on RP2040 / RP2350.
//   Library: make_sqisign_lib.sh cross-compiles the portable ref build with 32-bit field arithmetic (GF_RADIX=32) for
//   both CPUs (precompiled libsqisign.a). The runner picks the level: -DSQISIGN_LVL1 (p324_3, default),
//   -DSQISIGN_LVL3 (p500_27), -DSQISIGN_LVL5 (p664_17), and the big stack. Host stack peaks (keygen / sign / verify,
//   KB, no heap): I 73 / 102 / 39, III 97 / 136 / 62, V 131 / 185 / 82. Serial @115200.

#include <Arduino.h>
#include <string.h>
#include <pico/bootrom.h>
// a crash (e.g. past the big stack) drops to BOOTSEL: the runner reports it at once and can flash the next sketch
extern "C" void isr_hardfault(void) { reset_usb_boot(0, 0); }

extern "C" {
  #include <sqisign.h>
  int randombytes(unsigned char *x, unsigned long long xlen);
}

extern "C" int randombytes(unsigned char *x, unsigned long long xlen) {
  while (xlen >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, 4); x += 4; xlen -= 4; }
  if (xlen) { uint32_t r = rp2040.hwrand32(); for (unsigned long long i = 0; i < xlen; i++) x[i] = (uint8_t)(r >> (8 * i)); }
  return 0;
}

#ifndef BIG_STACK_BYTES   // the runner sets it per level (host peak + margin)
  #define BIG_STACK_BYTES (128u * 1024u)
#endif
#include "bigstack.h"

#ifndef ITERS
#define ITERS 5   // a signature takes seconds to minutes on the M0+
#endif
static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char sm[CRYPTO_BYTES + 32], m2[CRYPTO_BYTES + 32];
static unsigned char msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];
static unsigned long long g_smlen = 0, g_mlen2 = 0;
static uint32_t kpeak = 0, speak = 0, vpeak = 0;

static int th_keygen(void) { return crypto_sign_keypair(pk, sk); }
static int th_sign(void)   { return crypto_sign(sm, &g_smlen, msg, sizeof msg, sk); }
static int th_verify(void) { return crypto_sign_open(m2, &g_mlen2, sm, g_smlen, pk); }

static void print_label() { Serial.print(CRYPTO_ALGNAME); }

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
  Serial.print(F("=== ")); print_label(); Serial.println(F(" (SQIsign round 3, ref, 32-bit radix) on RP [big-stack] ==="));
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
