// liboqs_bench.ino - liboqs (bare-metal build, portable C) on RP2040 / RP2350: the same code the Pi/Mac run
//   through oqs-provider and the host liboqs stage, so Pi and Pico rows share an implementation. 0.16.0, or
//   liboqs main for the NIST round 3 MAYO / SNOVA / MQOM / UOV sets (the runner links the matching library).
//   One algorithm per build: the runner passes -DLB_ALG=<liboqs id> (e.g. ml_dsa_44) and only that
//   algorithm's code is linked, so the .uf2 size is its firmware cost. Same report format as the other
//   sketches, plus per-op PEAK STACK (painted big stack) - project plan 4.2.
//   Library: pico/sketches/liboqs_bench/make_liboqs_lib.sh (precompiled liboqs.a per CPU).
//   Failures are printed as results: "OUT OF MEMORY" (keys/signature don't fit the heap) and
//   "STACK OVERFLOW" (peak reached the big stack's end - raise -DLB_STACK_KB or the board can't).

#include <Arduino.h>
#include <liboqs.h>
#include <string.h>

#ifndef LB_ALG
#error "build with -DLB_ALG=<liboqs signature id>, e.g. -DLB_ALG=ml_dsa_44 (see run_benchmarks.py)"
#endif
#define LB_CAT3(a, b, c) a##b##c
#define LB_NEW(alg) LB_CAT3(OQS_SIG_, alg, _new)
#ifndef LB_ITERS
#define LB_ITERS 10
#endif
#if defined(__ARM_ARCH_6M__)
#define CHIP "RP2040"
#ifndef LB_STACK_KB
#define LB_STACK_KB 160
#endif
#else
#define CHIP "RP2350"
#ifndef LB_STACK_KB
#define LB_STACK_KB 400
#endif
#endif

static void rng(uint8_t *out, size_t n) {
  while (n >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(out, &r, 4); out += 4; n -= 4; }
  if (n) { uint32_t r = rp2040.hwrand32(); memcpy(out, &r, n); }
}

// ---- big SRAM stack + stack-pointer switch: validated on both boards ----
#define BIG_STACK_BYTES (LB_STACK_KB * 1024u)
static uint8_t g_bigstk[BIG_STACK_BYTES] __attribute__((aligned(16)));
#define STK_PAT 0x5A
#if defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__)
__attribute__((naked, noinline)) static int run_on_stack(void *new_top, int (*fn)(void)) {  // M33
  __asm volatile(
    "mrs  r2, msplim       \n"
    "mov  r3, sp           \n"
    "mov  sp, r0           \n"
    "movs r0, #0           \n"
    "msr  msplim, r0       \n"
    "push {r2, r3, r4, lr} \n"
    "blx  r1               \n"
    "pop  {r2, r3, r4, lr} \n"
    "msr  msplim, r2       \n"
    "mov  sp, r3           \n"
    "bx   lr               \n");
}
#else
__attribute__((naked, noinline)) static int run_on_stack(void *new_top, int (*fn)(void)) {  // M0+
  __asm volatile(
    "mov  r2, sp   \n"
    "mov  sp, r0   \n"
    "push {r2, lr} \n"
    "blx  r1       \n"
    "pop  {r2, r3} \n"
    "mov  sp, r2   \n"
    "bx   r3       \n");
}
#endif
static uint32_t big_stack_peak() {
  uint32_t i = 0; while (i < BIG_STACK_BYTES && g_bigstk[i] == STK_PAT) i++;
  return BIG_STACK_BYTES - i;
}

static OQS_SIG *sig;
static uint8_t *pk, *sk, *sm, msg[32];
static size_t sm_len;
static uint32_t tk[LB_ITERS], ts[LB_ITERS], tv[LB_ITERS], peak[3];

static int op_keygen() { return OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS ? 0 : 1; }
static int op_sign() { return OQS_SIG_sign(sig, sm, &sm_len, msg, sizeof msg, sk) == OQS_SUCCESS ? 0 : 1; }
static int op_verify() { return OQS_SIG_verify(sig, msg, sizeof msg, sm, sm_len, pk) == OQS_SUCCESS ? 0 : 1; }

// paint the big stack, time fn on it, record its peak stack; returns fn's result
static int timed(int (*fn)(void), uint32_t *us, uint32_t *pk_peak) {
  memset(g_bigstk, STK_PAT, BIG_STACK_BYTES);
  uint32_t t0 = micros();
  int r = run_on_stack(&g_bigstk[BIG_STACK_BYTES], fn);
  *us = micros() - t0;
  uint32_t p = big_stack_peak();
  if (p > *pk_peak) *pk_peak = p;
  return r;
}

static void report_op(const char *op, const uint32_t *t, int n) {
  static uint32_t srt[LB_ITERS];
  uint32_t mn = 0xFFFFFFFFu, mx = 0; uint64_t sum = 0;
  for (int i = 0; i < n; i++) { srt[i] = t[i]; sum += t[i]; if (t[i] < mn) mn = t[i]; if (t[i] > mx) mx = t[i]; }
  for (int i = 1; i < n; i++) { uint32_t k = srt[i]; int j = i - 1; while (j >= 0 && srt[j] > k) { srt[j + 1] = srt[j]; j--; } srt[j + 1] = k; }
  uint32_t mean = (uint32_t)(sum / n);
  uint32_t median = (n & 1) ? srt[n / 2] : (uint32_t)(((uint64_t)srt[n / 2 - 1] + srt[n / 2]) >> 1);
  uint64_t vsum = 0;
  for (int i = 0; i < n; i++) { int64_t d = (int64_t)t[i] - (int64_t)mean; vsum += (uint64_t)(d * d); }
  uint32_t sd = (uint32_t)sqrtf((float)(vsum / n)), mhz = F_CPU / 1000000u;
  Serial.print(sig->method_name); Serial.print(F("(liboqs)  ")); Serial.print(op);
  Serial.print(F("  n=")); Serial.print(n);
  Serial.print(F("  mean=")); Serial.print(mean); Serial.print(F("us/")); Serial.print(mean / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  median=")); Serial.print(median); Serial.print(F("us/")); Serial.print(median / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  std=")); Serial.print(sd); Serial.print(F("us/")); Serial.print(sd / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  min=")); Serial.print(mn); Serial.print(F("us  max=")); Serial.print(mx); Serial.print(F("us"));
  Serial.print(F("  mean_cyc=")); Serial.print((unsigned long)((uint64_t)mean * mhz));
  Serial.print(F("  median_cyc=")); Serial.print((unsigned long)((uint64_t)median * mhz));
  Serial.print(F("  ops/s=")); Serial.println(mean ? 1000000.0f / mean : 0.0f, 4); Serial.flush();
}

static void run_report() {
  Serial.print(F(">>> running, ITERS=")); Serial.print(LB_ITERS);
  Serial.print(F(" big stack=")); Serial.print(LB_STACK_KB); Serial.println(F(" KB")); Serial.flush();
  if (!sig) sig = LB_NEW(LB_ALG)();
  if (!sig) { Serial.println(F("!! algorithm not in this liboqs build (make_liboqs_lib.sh ALGS)")); return; }
  if (!pk) {
    pk = (uint8_t *)malloc(sig->length_public_key);
    sk = (uint8_t *)malloc(sig->length_secret_key);
    sm = (uint8_t *)malloc(sig->length_signature);
  }
  if (!pk || !sk || !sm) {
    Serial.print(F("=== ")); Serial.print(sig->method_name); Serial.println(F(" (liboqs) on " CHIP " ==="));
    Serial.print(F("!! OUT OF MEMORY: pk+sk+sig = "));
    Serial.print((unsigned long)(sig->length_public_key + sig->length_secret_key + sig->length_signature));
    Serial.print(F(" B, free heap ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" B"));
    Serial.println(F("=== done (runtime memory failure) ==="));
    return;
  }
  int okv = 0;
  for (int i = 0; i < LB_ITERS; i++) {
    msg[0] = (uint8_t)i;
    if (timed(op_keygen, &tk[i], &peak[0]) || timed(op_sign, &ts[i], &peak[1])) {
      Serial.print(F("!! keygen/sign failed at iter ")); Serial.println(i + 1); return;
    }
    if (timed(op_verify, &tv[i], &peak[2]) == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(LB_ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.print(F("=== ")); Serial.print(sig->method_name);
  Serial.print(F(" (liboqs " OQS_VERSION_TEXT ", portable C) on " CHIP " ==="));  Serial.println();
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz"));
  Serial.print(F("sizes: pk=")); Serial.print((unsigned)sig->length_public_key);
  Serial.print(F(" sk=")); Serial.print((unsigned)sig->length_secret_key);
  Serial.print(F(" sig=")); Serial.print((unsigned)sm_len);
  Serial.print(F(" sigMax=")); Serial.println((unsigned)sig->length_signature);
  report_op("keygen", tk, LB_ITERS);
  report_op("sign", ts, LB_ITERS);
  report_op("verify", tv, LB_ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print('/'); Serial.println(LB_ITERS);
  Serial.print(F("peak stack: keygen=")); Serial.print(peak[0]); Serial.print(F(" sign=")); Serial.print(peak[1]);
  Serial.print(F(" verify=")); Serial.print(peak[2]); Serial.print(F(" / ")); Serial.print(BIG_STACK_BYTES); Serial.println(F(" bytes"));
  if (peak[0] >= BIG_STACK_BYTES || peak[1] >= BIG_STACK_BYTES || peak[2] >= BIG_STACK_BYTES)
    Serial.println(F("!! STACK OVERFLOW: peak hit the big stack's end - numbers are not trustworthy"));
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
