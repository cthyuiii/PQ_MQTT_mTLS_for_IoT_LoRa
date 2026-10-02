/* mldsa87_bench.ino, verbatim except include paths: "src/x" -> "x", "x" -> "../x" for files beside the sketch (this file lives in src/) */
// mldsa87_bench.ino - ML-DSA-87 (FIPS 204) signature benchmark on RP2040 / Pico W.
//   mldsa-native 'ref' (liboqs lineage) + PQClean fips202.c (src/). Board: Raspberry Pi Pico W.
//   NOTE: ML-DSA-87 has the largest stack footprint (~tens-to->100 KB). It relies on the
//   RP2040 stack growing into the (empty) heap arena. If it resets instead of printing,
//   that's a stack overflow - tell Claude to move it onto a dedicated large stack.
#include <Arduino.h>

#include <string.h>

#define MLDSA_PK 2592
#define MLDSA_SK 4896
#define MLDSA_SIG 4627

extern "C" {
  int PQCP_MLDSA_NATIVE_MLDSA87_C_keypair(uint8_t *pk, uint8_t *sk);
  int PQCP_MLDSA_NATIVE_MLDSA87_C_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
  int PQCP_MLDSA_NATIVE_MLDSA87_C_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
  int randombytes(uint8_t *out, size_t n);
}
extern "C" int randombytes(uint8_t *out, size_t n) {
  while (n >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(out, &r, 4); out += 4; n -= 4; }
  if (n) { uint32_t r = rp2040.hwrand32(); for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(r >> (8 * i)); }
  return 0;
}

#define ITERS 20
static uint8_t pk[MLDSA_PK], sk[MLDSA_SK], sig[MLDSA_SIG];
static uint8_t msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];

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
  Serial.print("ML-DSA-87(mldsa-native)  "); Serial.print(op);
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
  int okv = 0; size_t siglen = 0;
  for (int i = 0; i < ITERS; i++) {
    msg[0] = (uint8_t)i;
    uint32_t t0 = micros(); PQCP_MLDSA_NATIVE_MLDSA87_C_keypair(pk, sk); uint32_t t1 = micros();
    PQCP_MLDSA_NATIVE_MLDSA87_C_signature(sig, &siglen, msg, sizeof msg, NULL, 0, sk); uint32_t t2 = micros();
    int r = PQCP_MLDSA_NATIVE_MLDSA87_C_verify(sig, siglen, msg, sizeof msg, NULL, 0, pk); uint32_t t3 = micros();
    tk[i] = t1 - t0; ts[i] = t2 - t1; tv[i] = t3 - t2; if (r == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== ML-DSA-87 (mldsa-native ref) on RP2040 ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print(MLDSA_PK); Serial.print(F(" sk=")); Serial.print(MLDSA_SK);
  Serial.print(F(" sig=")); Serial.print((int)siglen); Serial.print(F(" sigMax=")); Serial.print(MLDSA_SIG); Serial.println();
  report_op("keygen", tk, ITERS); report_op("sign", ts, ITERS); report_op("verify", tv, ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
  Serial.print(F("free stack: ")); Serial.print(rp2040.getFreeStack());
  Serial.print(F(" bytes   free heap: ")); Serial.print(rp2040.getFreeHeap()); Serial.println(F(" bytes"));
  Serial.println(F("=== done (repeats in ~5s) ==="));
}
void setup() { Serial.begin(115200); while (!Serial) delay(10); delay(200); 
}
void loop() { run_report(); delay(5000); }
