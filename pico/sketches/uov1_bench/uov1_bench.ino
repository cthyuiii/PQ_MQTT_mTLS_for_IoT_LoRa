// uov1_bench.ino - UOV ov-Ip (classic, GF(256), n=112 o=44, NIST L1) on RP2040 / RP2350.
//
//   Source: pqov/pqov reference impl (CC0/Apache-2.0), variant _OV_CLASSIC, PROJ=ref, flattened
//   into src/. Configured to the PORTABLE backend (no OpenSSL): bundled PQClean fips202 (SHAKE256)
//   + the repo's 4-round bitsliced AES (aes128_4r_ffs.c) for the public-matrix PRG. Host-verified
//   (keygen->sign->verify->tamper) and the baked keypair self-checks before embedding.
//
//   RAM REALITY: pk=278432 B (272 KB) + sk=237896 B (232 KB). KEYGEN materialises BOTH at once
//   (~504 KB scratch) -> infeasible even on the RP2350's 520 KB. So keygen is NOT run on-device:
//   a deterministic keypair is precomputed on host and baked into flash (baked_keys.h). ov_sign /
//   ov_verify take the key by const pointer (read straight from flash/XIP) and use only a few KB
//   of stack -> sign + verify run on BOTH boards. Board: "Raspberry Pi Pico". Serial @115200.

#include <Arduino.h>
#include <string.h>

extern "C" {
  #include "src/api.h"
  #include "src/utils_randombytes.h"   // remaps randombytes -> pqov namespace
  int crypto_sign_signature(unsigned char *sig, unsigned long long *siglen,
                            const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
  int crypto_sign_verify(const unsigned char *sig, unsigned long long siglen,
                         const unsigned char *m, unsigned long long mlen, const unsigned char *pk);
}
#include "src/baked_keys.h"            // const uov_pk[278432], uov_sk[237896]  (live in flash)
#define UOV_LABEL "UOV-Ip"

extern "C" void randombytes(unsigned char *x, unsigned long long xlen) {
  while (xlen >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(x, &r, 4); x += 4; xlen -= 4; }
  if (xlen) { uint32_t r = rp2040.hwrand32(); for (unsigned long long i = 0; i < xlen; i++) x[i] = (uint8_t)(r >> (8 * i)); }
}

// classic sign / verify need only a few KB of stack; the 32 KB big-stack is harmless (pk and sk stay in flash).
#define BIG_STACK_BYTES (32u * 1024u)
#include "bigstack.h"

#define ITERS 20
static unsigned char sig[CRYPTO_BYTES];
static unsigned char msg[32] = {0};
static uint32_t ts[ITERS], tv[ITERS];
static unsigned long long g_sl = 0;
static int th_sign(void)   { return crypto_sign_signature(sig, &g_sl, msg, sizeof msg, uov_sk); }
static int th_verify(void) { return crypto_sign_verify(sig, g_sl, msg, sizeof msg, uov_pk); }

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
  Serial.print(F("  mean_cyc=")); Serial.print((unsigned long)((uint64_t)mean * mhz));
  Serial.print(F("  median_cyc=")); Serial.print((unsigned long)((uint64_t)median * mhz));
  Serial.print(F("  ops/s=")); Serial.println(ops, 4); Serial.flush();
}

static void run_report() {
  Serial.print(F(">>> running, ITERS=")); Serial.println(ITERS); Serial.flush();
  int okv = 0;
  for (int i = 0; i < ITERS; i++) {
    msg[0] = (uint8_t)i;
    big_stack_paint(); uint32_t b0 = micros(); int rs = big_stack_run(th_sign);   uint32_t b1 = micros();
    big_stack_paint(); uint32_t c0 = micros(); int rv = big_stack_run(th_verify); uint32_t c1 = micros();
    ts[i] = b1 - b0; tv[i] = c1 - c0;
    (void)rs;
    if (rv == 0) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" s=")); Serial.print(ts[i]); Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== UOV ov-Ip classic (GF256, n112 o44, L1) on RP2040 [keys in flash] ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.print(F("sizes: pk=")); Serial.print((long)CRYPTO_PUBLICKEYBYTES);
  Serial.print(F(" sk=")); Serial.print((long)CRYPTO_SECRETKEYBYTES);
  Serial.print(F(" sigMax=")); Serial.print((long)CRYPTO_BYTES); Serial.print(F(" sig=")); Serial.println((long)CRYPTO_BYTES);
  Serial.println(F("keygen: N/A on-device (needs ~504 KB scratch > RP2350 520 KB); keypair baked in flash"));
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
