// Runs the Pico pipeline's LoRaWAN / CMAC / GCM / CCM / Ascon code (pico/sketches/mqtt_tls_bench/lora_aead.h) on the host against
// real BearSSL, and checks every frame it builds byte-for-byte against the host pipeline's (app_aead.c, OpenSSL).
#include <stdlib.h>
#include "lora_aead.h"
extern "C" {
#include "app_aead.h"
}
static const int SIZES[] = {16, 51, 115, 222};
int main() {
  int bad = 0;
  bad |= !cmac_kat();    printf("CMAC KAT (RFC 4493)           %s\n", cmac_kat() ? "OK" : "FAIL");
  bad |= !lorawan_kat(); printf("LoRaWAN up + 1.1 down vectors %s\n", lorawan_kat() ? "OK" : "FAIL");
  bad |= !ascon_kat();   printf("Ascon KAT                     %s\n", ascon_kat() ? "OK" : "FAIL");
  bad |= !cmac256_kat(); printf("CMAC-256 KAT (SP 800-38B)     %s\n", cmac256_kat() ? "OK" : "FAIL");
  bad |= !ccm_kat();     printf("CCM KAT (SP 800-38C ex. 1)    %s\n", ccm_kat() ? "OK" : "FAIL");
  srand(7);
  for (int i = 0; i < 32; i++) k_app[i] = (uint8_t)rand();
  for (int i = 0; i < 16; i++) { k_nwk[i] = (uint8_t)rand(); k_nwk2[i] = (uint8_t)rand(); }
  static unsigned char ref[300];
  for (int k = 0; k < LA_N; k++)  // every scheme, both directions: the Pico's frame == app_aead's
    for (int d = 0; d < 2; d++) {
      app_aead_init(LA[k].name); app_aead_set_keys(k_app, k_nwk, k_nwk2, devaddr);
      la_setup(k); down = d;
      for (int len : SIZES) {
        for (int i = 0; i < len; i++) pt[i] = (uint8_t)(i * 7 + k);
        fcnt = 40 + len - 1; LA[k].seal(len);                  // Pico code, fcnt becomes 40 + len
        int n = app_seal(d, 40 + len, pt, len, ref);           // host code, same fcnt and direction
        int same = n == HDR + len + LA[k].tag && memcmp(ref, frame, n) == 0;
        int rt = LA[k].open(len) == 0 && memcmp(out, pt, len) == 0;
        frame[HDR] ^= 1; int tamper = k == 0 || LA[k].open(len) != 0; frame[HDR] ^= 1;  // "none" has nothing to check
        bad |= !(same && rt && tamper);
        printf("%-9s %-4s %3d B: Pico frame == app_aead frame %s, round trip %s, tamper rejected %s\n",
               LA[k].name, d ? "down" : "up", len, same ? "yes" : "NO", rt ? "ok" : "FAIL", tamper ? "yes" : "NO");
      }
    }
  printf("%s\n", bad ? "HOST TEST FAILED" : "all Pico pipeline crypto checks pass on the host");
  return bad;
}
