// ecdsa_bench.ino - classical ECDSA baseline (BearSSL, bundled in the arduino-pico core) on RP2040 / RP2350.
//   One sketch for P-256 / SHA-256, P-384 / SHA-384 and P-521 / SHA-512 (was ecdsa_p256_bench, ecdsa_p384_bench,
//   ecdsa_p521_bench); run_benchmarks.py picks one with -DPICO_VARIANT_<curve>. P-256 uses BearSSL's
//   constant-time P-256-only code (m15); P-384 / P-521 need the generic implementation. Serial Monitor @115200.
#include <Arduino.h>

#include <bearssl/bearssl.h>

#if defined(PICO_VARIANT_p256)
#define LABEL "ECDSA-P256"
#define CURVE BR_EC_secp256r1
#define EC_IMPL (&br_ec_p256_m15)
#define HASH(x) br_sha256_##x
#define PK_SK "pk=64 (uncompressed-1) sk=32"
#elif defined(PICO_VARIANT_p384)
#define LABEL "ECDSA-P384"
#define CURVE BR_EC_secp384r1
#define EC_IMPL br_ec_get_default()
#define HASH(x) br_sha384_##x
#define PK_SK "pk=96 sk=48"
#elif defined(PICO_VARIANT_p521)
#define LABEL "ECDSA-P521"
#define CURVE BR_EC_secp521r1
#define EC_IMPL br_ec_get_default()
#define HASH(x) br_sha512_##x
#define PK_SK "pk=132 sk=66"
#else
#error "build with -DPICO_VARIANT_<curve>, curve = p256 | p384 | p521"
#endif
#define HASH_LEN (HASH(SIZE))

static br_hmac_drbg_context rng;
static void rng_init() {
  br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
  for (int i = 0; i < 12; i++) { uint32_t r = rp2040.hwrand32(); br_hmac_drbg_update(&rng, &r, sizeof r); }
}

#define ITERS 20
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
  Serial.print(LABEL "  "); Serial.print(op);
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
  const br_ec_impl *ec = EC_IMPL;
  unsigned char skbuf[BR_EC_KBUF_PRIV_MAX_SIZE], pkbuf[BR_EC_KBUF_PUB_MAX_SIZE];
  br_ec_private_key sk; br_ec_public_key pk;
  unsigned char msg[32], hv[HASH_LEN], sig[140];

  Serial.println();
  Serial.println(F("=== " LABEL " (BearSSL, classical baseline) on RP2040 ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.flush();

  int okv = 0; size_t siglen = 0;
  for (int i = 0; i < ITERS; i++) {
    for (int j = 0; j < 32; j++) msg[j] = (uint8_t)(i + j);
    HASH(context) hc; HASH(init)(&hc); HASH(update)(&hc, msg, 32); HASH(out)(&hc, hv);

    uint32_t t0 = micros();
    br_ec_keygen(&rng.vtable, ec, &sk, skbuf, CURVE);
    br_ec_compute_pub(ec, &pk, pkbuf, &sk);
    uint32_t t1 = micros();
    siglen = br_ecdsa_i31_sign_raw(ec, &HASH(vtable), hv, &sk, sig);
    uint32_t t2 = micros();
    uint32_t ok = br_ecdsa_i31_vrfy_raw(ec, hv, HASH_LEN, &pk, sig, siglen);
    uint32_t t3 = micros();

    tk[i] = t1 - t0; ts[i] = t2 - t1; tv[i] = t3 - t2;
    if (ok == 1) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.print(F("sizes: " PK_SK " sigMax=")); Serial.print((int)siglen); Serial.print(F(" sig=")); Serial.println((int)siglen);
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
  rng_init();
}

void loop() {
  run_report();
  delay(5000);
}
