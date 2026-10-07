// uov_bench.ino - UOV-Ip round 3 (classic: GF(256), n=119, o=45, NIST L1) sign / verify on RP2040 / RP2350.
//
//   Code: the Pico's round 3 liboqs (liboqs_bench/make_liboqs_lib.sh LIBOQS_ROUND=3, pqov's ref code).
//   Keys: pk 321,300 B + sk 278,087 B. Keygen holds both in RAM (~600 KB), more than either board has, so
//   make_uov_keys.sh makes the pair on the host from the same liboqs commit; the runner passes its uov_keys.h
//   with -I. Sign and verify read the keys straight from flash (XIP) and need 12 / 5.3 KB of stack, no heap
//   (the M0+ build in QEMU). Serial @115200.

#include <Arduino.h>
#include <liboqs.h>
#include <pico/bootrom.h>
#include <string.h>
#include "uov_keys.h"  // const uov_pk[], uov_sk[]: they stay in flash
#define UOV_LABEL "UOV-Ip round 3"

// a crash drops to BOOTSEL: the runner reports it at once and can flash the next sketch
extern "C" void isr_hardfault(void) { reset_usb_boot(0, 0); }

static void rng(uint8_t *x, size_t n) {
  while (n >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, 4); x += 4; n -= 4; }
  if (n) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, n); }
}

#define BIG_STACK_BYTES (32u * 1024u)
#include "bigstack.h"

#define ITERS 20
static unsigned char sig[UOV_SIG_BYTES];
static unsigned char msg[32] = {0};
static uint32_t ts[ITERS], tv[ITERS];
static size_t g_sl = 0;
static uint32_t speak = 0, vpeak = 0;
static int th_sign(void)   { return OQS_SIG_uov_ov_Ip_sign(sig, &g_sl, msg, sizeof msg, uov_sk); }
static int th_verify(void) { return OQS_SIG_uov_ov_Ip_verify(msg, sizeof msg, sig, g_sl, uov_pk); }

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
  Serial.print(UOV_LABEL "  "); Serial.print(op);
  Serial.print(F("  n=")); Serial.print(n);
  Serial.print(F("  mean=")); Serial.print(mean); Serial.print(F("us/")); Serial.print(mean / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  median=")); Serial.print(median); Serial.print(F("us/")); Serial.print(median / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  std=")); Serial.print(sd); Serial.print(F("us/")); Serial.print(sd / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  min=")); Serial.print(mn); Serial.print(F("us  max=")); Serial.print(mx); Serial.print(F("us"));
  Serial.print(F("  mean_cyc=")); Serial.print((unsigned long long)mean * mhz);
  Serial.print(F("  median_cyc=")); Serial.print((unsigned long long)median * mhz);
  Serial.print(F("  ops/s=")); Serial.println(ops, 4); Serial.flush();
}

static void run_report() {
  Serial.print(F(">>> running " UOV_LABEL ", ITERS=")); Serial.println(ITERS); Serial.flush();
  int okv = 0, bad = 0;
  for (int i = 0; i < ITERS; i++) {
    msg[0] = (uint8_t)i;
    big_stack_paint(); uint32_t b0 = micros(); int rs = big_stack_run(th_sign);   uint32_t b1 = micros();
    { uint32_t p = big_stack_peak(); if (p > speak) speak = p; }
    big_stack_paint(); uint32_t c0 = micros(); int rv = big_stack_run(th_verify); uint32_t c1 = micros();
    { uint32_t p = big_stack_peak(); if (p > vpeak) vpeak = p; }
    ts[i] = b1 - b0; tv[i] = c1 - c0;
    if (rs == OQS_SUCCESS && rv == OQS_SUCCESS) okv++;
    msg[1] ^= 1; bad += big_stack_run(th_verify) == OQS_SUCCESS; msg[1] ^= 1;  // a changed message must fail
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" s=")); Serial.print(ts[i]); Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== " UOV_LABEL " (liboqs main, classic, keys in flash) on RP [big-stack] ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print((long)UOV_PK_BYTES);
  Serial.print(F(" sk=")); Serial.print((long)UOV_SK_BYTES);
  Serial.print(F(" sigMax=")); Serial.print((long)UOV_SIG_BYTES); Serial.print(F(" sig=")); Serial.println((long)g_sl);
  Serial.println(F("keygen: on the host (make_uov_keys.sh): both keys at once need ~600 KB of RAM"));
  report_op("sign",   ts, ITERS);
  report_op("verify", tv, ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
  Serial.print(F("tampered messages accepted: ")); Serial.println(bad);
  Serial.print(F("big-stack peak: sign=")); Serial.print(speak); Serial.print(F(" verify=")); Serial.print(vpeak);
  Serial.print(F(" / ")); Serial.print(BIG_STACK_BYTES); Serial.println(F(" bytes"));
  Serial.print(F("free heap: ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" bytes"));
  Serial.println(F("=== done (repeats in ~5s) ==="));
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  delay(200);
  OQS_init();
  OQS_randombytes_custom_algorithm(rng);
}

void loop() {
  run_report();
  delay(5000);
}
