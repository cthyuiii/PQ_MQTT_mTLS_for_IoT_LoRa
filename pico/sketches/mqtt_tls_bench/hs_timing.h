// hs_timing.h - the client's crypto inside each TLS handshake (hs_timing.c): what a connection row adds as HS_COLS
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
enum { HS_KEYGEN, HS_DERIVE, HS_VERIFY, HS_SIGN, HS_N };  // key share, its completion, verify, sign
typedef struct { double us[HS_N]; unsigned n[HS_N]; } hs_times_t;
extern hs_times_t hs_t;
static inline void hs_reset(void) { hs_times_t z = {{0}, {0}}; hs_t = z; }
#define HS_COLS "hs_keygen_us,hs_derive_us,hs_verify_us,hs_sign_us,hs_keygen_n,hs_derive_n,hs_verify_n,hs_sign_n"
#define HS_FMT ",%.1f,%.1f,%.1f,%.1f,%u,%u,%u,%u"
#define HS_ARGS(h) (h).us[0], (h).us[1], (h).us[2], (h).us[3], (h).n[0], (h).n[1], (h).n[2], (h).n[3]
#ifdef __cplusplus
}
#endif
