/* faest_128f_bench.ino, verbatim except include paths: "src/x" -> "x", "x" -> "../x" for files beside the sketch (this file lives in src/) */
// faest_128f_bench.ino - FAEST-128f (FAEST 3.0, NIST additional signatures round 3; VOLE-in-the-head) on RP2040 / Pico W.
//   Source: faest-ref v3.0.0 (pure-C AES, no OpenSSL; bundled Keccak), generated + flattened into src/ by update_src.sh.
//   Build flags baked into src/faest_config_pico.h (HAVE_RANDOMBYTES + PQCLEAN, no autoconf config.h).
//   Host-verified (open=OK). MPCitH = compute-heavy; n low. Board: "Raspberry Pi Pico W". Serial @115200.

#include <Arduino.h>
#include <board_compat.h>

#include <string.h>

extern "C" {
  #include "api.h"
  // FAEST (PQCLEAN path) expects void randombytes(uint8_t*, size_t)
  void randombytes(uint8_t *x, size_t xlen);
}

extern "C" void randombytes(uint8_t *x, size_t xlen) {
  while (xlen >= 4) { uint32_t r = board_hwrand32(); memcpy(x, &r, 4); x += 4; xlen -= 4; }
  if (xlen) { uint32_t r = board_hwrand32(); for (size_t i = 0; i < xlen; i++) x[i] = (uint8_t)(r >> (8 * i)); }
}

#define ITERS 1
static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char sm[CRYPTO_BYTES + 32], m2[CRYPTO_BYTES + 32];
static unsigned char msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];
BOARD_CYC_ARRAY(ck, ITERS) BOARD_CYC_ARRAY(cs, ITERS) BOARD_CYC_ARRAY(cv, ITERS)

static void report_op(const char *op, const uint32_t *t, int n BOARD_CYC_PARAM(c)) {
  uint32_t mn = 0xFFFFFFFFu, mx = 0; uint64_t sum = 0;
  static uint32_t srt[ITERS];
  for (int i = 0; i < n; i++) { uint32_t v = t[i]; srt[i] = v; sum += v; if (v < mn) mn = v; if (v > mx) mx = v; }
  for (int i = 1; i < n; i++) { uint32_t k = srt[i]; int j = i - 1; while (j >= 0 && srt[j] > k) { srt[j+1] = srt[j]; j--; } srt[j+1] = k; }
  uint32_t mean = (uint32_t)(sum / n);
  uint32_t median = (n & 1) ? srt[n/2] : (uint32_t)(((uint64_t)srt[n/2-1] + srt[n/2]) >> 1);
  uint64_t vsum = 0;
  for (int i = 0; i < n; i++) { int64_t d = (int64_t)t[i] - (int64_t)mean; vsum += (uint64_t)(d * d); }
  uint32_t sd = (uint32_t)sqrtf((float)(vsum / (n > 0 ? n : 1)));
  uint32_t mhz = board_cpu_mhz();
  float ops = (mean > 0) ? (1000000.0f / (float)mean) : 0.0f;
  Serial.print("FAEST-128f  "); Serial.print(op);
  Serial.print(F("  n=")); Serial.print(n);
  Serial.print(F("  mean=")); Serial.print(mean); Serial.print(F("us/")); Serial.print(mean / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  median=")); Serial.print(median); Serial.print(F("us/")); Serial.print(median / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  std=")); Serial.print(sd); Serial.print(F("us/")); Serial.print(sd / 1000.0f, 3); Serial.print(F("ms"));
  Serial.print(F("  min=")); Serial.print(mn); Serial.print(F("us  max=")); Serial.print(mx); Serial.print(F("us"));
#if BOARD_HW_CYCLES
  board_print_cyc_stats(c, n);
#else
  Serial.print(F("  mean_cyc=")); Serial.print((unsigned long)((uint64_t)mean * mhz));
  Serial.print(F("  median_cyc=")); Serial.print((unsigned long)((uint64_t)median * mhz));
#endif
  Serial.print(F("  ops/s=")); Serial.println(ops, 4); Serial.flush();
}

static void run_report() {
  Serial.print(F(">>> running, ITERS=")); Serial.println(ITERS); Serial.flush();
  int okv = 0; unsigned long long smlen = 0, mlen2 = 0;
  for (int i = 0; i < ITERS; i++) {
    msg[0] = (uint8_t)i;
    BOARD_STAMP(t0); crypto_sign_keypair(pk, sk);        BOARD_STAMP(t1);
    crypto_sign(sm, &smlen, msg, sizeof msg, sk);               BOARD_STAMP(t2);
    int r = crypto_sign_open(m2, &mlen2, sm, smlen, pk);        BOARD_STAMP(t3);
    tk[i] = t1 - t0; BOARD_LAP(ck[i], t0, t1); ts[i] = t2 - t1; BOARD_LAP(cs[i], t1, t2); tv[i] = t3 - t2; BOARD_LAP(cv[i], t2, t3);
    if (r == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.print(F("us")); BOARD_PRINT_CYC("kc", ck[i]); BOARD_PRINT_CYC("sc", cs[i]); BOARD_PRINT_CYC("vc", cv[i]); Serial.println(); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== FAEST-128f (ref, pure-C AES, MPCitH) on " BOARD_CHIP " ==="));
  Serial.print(F("CPU clock: ")); Serial.print(board_cpu_mhz()); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print(CRYPTO_PUBLICKEYBYTES);
  Serial.print(F(" sk=")); Serial.print(CRYPTO_SECRETKEYBYTES);
  Serial.print(F(" sigMax=")); Serial.print(CRYPTO_BYTES); Serial.print(F(" sig=")); Serial.println((int)(smlen - 32));
  report_op("keygen", tk, ITERS BOARD_CYC_ARG(ck));
  report_op("sign", ts, ITERS BOARD_CYC_ARG(cs));
  report_op("verify", tv, ITERS BOARD_CYC_ARG(cv));
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
  Serial.print(F("free stack: ")); Serial.print(board_free_stack());
  Serial.print(F(" bytes   free heap: ")); Serial.print(board_free_heap()); Serial.println(F(" bytes"));
  Serial.println(F("=== done (repeats in ~5s) ==="));
}

void setup() {
  Serial.begin(115200);
  // Wait for the Serial Monitor to attach BEFORE doing heavy crypto, so the board
  // stays responsive to the USB connect handshake (avoids monitor-connect timeouts).
  while (!Serial) delay(10);
  delay(200);
}

void loop() {
  run_report();
  delay(5000);
}
