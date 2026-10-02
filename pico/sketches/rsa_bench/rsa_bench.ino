// rsa_bench.ino - classical RSA baseline, PKCS#1 v1.5 (BearSSL, bundled in the arduino-pico core), on RP2040 /
//   RP2350. One sketch for RSA-2048 / SHA-256, RSA-3072 / SHA-384 and RSA-4096 / SHA-512 (was rsa2048_bench,
//   rsa3072_bench, rsa4096_bench); run_benchmarks.py picks one with -DPICO_VARIANT_<bits>.
//   Keygen is a randomized prime search: slow and highly variable on a Cortex-M0+ (tens of seconds for 2048,
//   often more than 10 minutes for 4096), hence the per-stage prints that keep the runner's idle timeout alive.
//   Serial Monitor @115200.
#include <Arduino.h>

#include <bearssl/bearssl.h>

#if defined(PICO_VARIANT_2048)
#define RSA_BITS 2048
#define HASH(x) br_sha256_##x
#define HASH_OID BR_HASH_OID_SHA256
#define HASH_NAME "SHA-256"
#elif defined(PICO_VARIANT_3072)
#define RSA_BITS 3072
#define HASH(x) br_sha384_##x
#define HASH_OID BR_HASH_OID_SHA384
#define HASH_NAME "SHA-384"
#elif defined(PICO_VARIANT_4096)
#define RSA_BITS 4096
#define HASH(x) br_sha512_##x
#define HASH_OID BR_HASH_OID_SHA512
#define HASH_NAME "SHA-512"
#else
#error "build with -DPICO_VARIANT_<bits>, bits = 2048 | 3072 | 4096"
#endif
#define HASH_LEN (HASH(SIZE))
#define STR_(x) #x
#define STR(x) STR_(x)
#define LABEL "RSA-" STR(RSA_BITS)

static br_hmac_drbg_context rng;
static void rng_init() {
  br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
  for (int i = 0; i < 12; i++) { uint32_t r = rp2040.hwrand32(); br_hmac_drbg_update(&rng, &r, sizeof r); }
}

#define ITERS 3
static unsigned char kbuf_priv[BR_RSA_KBUF_PRIV_SIZE(RSA_BITS)];
static unsigned char kbuf_pub [BR_RSA_KBUF_PUB_SIZE(RSA_BITS)];
static unsigned char sig[RSA_BITS / 8];
static br_rsa_private_key sk;
static br_rsa_public_key  pk;
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
  Serial.println();
  Serial.println(F("=== " LABEL " PKCS#1v1.5/" HASH_NAME " (BearSSL, classical baseline) on RP2040 ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.flush();

  unsigned char msg[32], hv[HASH_LEN], hv2[HASH_LEN];
  for (int j = 0; j < 32; j++) msg[j] = (uint8_t)j;
  HASH(context) hc; HASH(init)(&hc); HASH(update)(&hc, msg, 32); HASH(out)(&hc, hv);

  br_rsa_keygen     kg   = br_rsa_keygen_get_default();
  br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
  br_rsa_pkcs1_vrfy vrfy = br_rsa_pkcs1_vrfy_get_default();

  int okv = 0;
  for (int i = 0; i < ITERS; i++) {
    Serial.print(F("[iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F("] keygen(slow)...")); Serial.flush();
    uint32_t t0 = micros();
    uint32_t kok = kg(&rng.vtable, &sk, kbuf_priv, &pk, kbuf_pub, RSA_BITS, 0 /*default e=65537*/);
    uint32_t t1 = micros();
    Serial.print(' '); Serial.print(t1 - t0); Serial.print(F("us (ok=")); Serial.print(kok); Serial.print(F(")  sign...")); Serial.flush();
    uint32_t sok = sign(HASH_OID, hv, HASH_LEN, &sk, sig);
    uint32_t t2 = micros();
    Serial.print(' '); Serial.print(t2 - t1); Serial.print(F("us  verify...")); Serial.flush();
    uint32_t vok = vrfy(sig, sizeof sig, HASH_OID, HASH_LEN, &pk, hv2);
    uint32_t t3 = micros();
    int good = (sok == 1) && (vok == 1) && (memcmp(hv, hv2, HASH_LEN) == 0);
    Serial.print(' '); Serial.print(t3 - t2); Serial.print(F("us  ok=")); Serial.println(good);

    tk[i] = t1 - t0; ts[i] = t2 - t1; tv[i] = t3 - t2;
    if (good) okv++;
  }
  report_op("keygen", tk, ITERS);
  report_op("sign",   ts, ITERS);
  report_op("verify", tv, ITERS);
  Serial.print(F("sizes: pk=")); Serial.print((int)((RSA_BITS + 7) / 8)); Serial.print(F(" (n) e=3  sigMax=")); Serial.print((int)sizeof sig); Serial.print(F(" sig=")); Serial.println((int)sizeof sig);
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
