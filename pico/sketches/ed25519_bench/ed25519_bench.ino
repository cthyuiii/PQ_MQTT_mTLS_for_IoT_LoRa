// ed25519_bench.ino - classical Ed25519 (RFC 8032) baseline on RP2040 / Pico (and RP2350).
//
//   Ed25519 is NOT in BearSSL, so this sketch uses the well-known Arduino "Crypto" library by
//   Rhys Weatherley (rweather/arduinolibs), which provides a portable, BSD-licensed Ed25519.
//   INSTALL IT ONCE (either the Arduino IDE Library Manager -> search "Crypto" by Rhys
//   Weatherley, or:  arduino-cli lib install Crypto ). Then this compiles and runs.
//
//   Ed25519: private key 32 B, public key 32 B, signature 64 B. Fast on the M0+ (and much
//   faster on the M33/RP2350 with its hardware multiplier).
//   Board: "Raspberry Pi Pico". Serial Monitor @115200.

#include <Arduino.h>
#include <Ed25519.h>          // from the "Crypto" library (rweather/arduinolibs)

#define ITERS 20
static uint8_t priv[32], pub[32], sig[64];
static uint8_t msg[32] = {0};
static uint32_t tk[ITERS], ts[ITERS], tv[ITERS];

static void fill_random(uint8_t *p, size_t n) {           // Ed25519 private key = 32 random bytes
  while (n >= 4) { uint32_t r = rp2040.hwrand32(); memcpy(p, &r, 4); p += 4; n -= 4; }
  if (n) { uint32_t r = rp2040.hwrand32(); for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(r >> (8 * i)); }
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
  Serial.print("Ed25519  "); Serial.print(op);
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
    uint32_t t0 = micros();
    fill_random(priv, 32);
    Ed25519::derivePublicKey(pub, priv);            // keygen (scalar mult is the cost)
    uint32_t t1 = micros();
    Ed25519::sign(sig, priv, pub, msg, sizeof msg); // sign
    uint32_t t2 = micros();
    bool ok = Ed25519::verify(sig, pub, msg, sizeof msg);  // verify
    uint32_t t3 = micros();
    tk[i] = t1 - t0; ts[i] = t2 - t1; tv[i] = t3 - t2;
    if (ok) okv++;
    Serial.print(F("  iter ")); Serial.print(i + 1); Serial.print('/'); Serial.print(ITERS);
    Serial.print(F(" k=")); Serial.print(tk[i]); Serial.print(F("us s=")); Serial.print(ts[i]);
    Serial.print(F("us v=")); Serial.print(tv[i]); Serial.println(F("us")); Serial.flush();
  }
  Serial.println();
  Serial.println(F("=== Ed25519 (RFC 8032, rweather Crypto lib) on RP2040 ==="));
  Serial.print(F("CPU clock: ")); Serial.print(F_CPU / 1000000u); Serial.println(F(" MHz")); Serial.flush();
  Serial.println(F("sizes: pk=32 sk=32 sigMax=64 sig=64"));
  report_op("keygen", tk, ITERS);
  report_op("sign",   ts, ITERS);
  report_op("verify", tv, ITERS);
  Serial.print(F("verify OK: ")); Serial.print(okv); Serial.print("/"); Serial.println(ITERS);
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
