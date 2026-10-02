/* sig_speed.c - Stage 1 keygen / sign / verify microbenchmark: one timing harness for three libraries,
 * with REAL cycle counts on Linux (perf_event_open) and Apple Silicon macOS (kperf private framework), and a
 * clock_gettime fallback elsewhere (cycles column = 0).
 *
 *   default         OpenSSL EVP (+ oqs-provider): PQC pure (md = NULL), RSA / ECDSA over SHA-256
 *   -DSIG_LIBOQS    liboqs directly: OQS_SIG_keypair / sign / verify (liboqs names)
 *   -DSIG_WOLFSSL   wolfCrypt directly: RSA, ECDSA P-256, Ed25519, ML-DSA, Falcon, SLH-DSA (Stage 1 names)
 *
 * Every library runs the same loop: the same 64-byte message, the same N timed calls per operation for every
 * algorithm, one key pair for sign / verify. Only the operation itself is inside the timer:
 *   keygen = EVP_PKEY_generate | OQS_SIG_keypair | wc_*MakeKey     (context / key object set up outside)
 *   sign   = EVP_DigestSign    | OQS_SIG_sign    | wc_*Sign
 *   verify = EVP_DigestVerify  | OQS_SIG_verify  | wc_*Verify
 * OpenSSL's one-shot calls also need EVP_DigestSign/VerifyInit_ex before each call (a TLS handshake pays it
 * too). That is timed on its own and reported as the extra ops sign_setup / verify_setup, not in sign / verify.
 *
 * Build:
 *   cc -O2 sig_speed.c -o openssl_sig_speed -I$O/include -L$O/lib -lcrypto -lm        (OpenSSL in $O)
 *   cc -O2 -DSIG_LIBOQS  sig_speed.c -o liboqs_sig_speed  -I$P/include -L$P/lib -Wl,-rpath,$P/lib -loqs -lm
 *   cc -O2 -DSIG_WOLFSSL sig_speed.c -o wolfssl_sig_speed -I$W/include -L$W/lib -Wl,-rpath,$W/lib -lwolfssl -lm
 * Run:
 *   ./openssl_sig_speed <iterations> <spec> [spec...]     e.g. 100 ML-DSA-44 falcon512 mayo1 EC:P-256 RSA:3072
 *   For oqs-provider names, set OPENSSL_MODULES to the dir with oqsprovider.*.
 *   Real cycles on Linux may need:  sudo sysctl kernel.perf_event_paranoid=1
 *   Real cycles on Apple Silicon REQUIRE root (kperf is a private API; on failure cycles = 0, timings stay valid).
 *
 * Output CSV (stdout): algo,op,n,mean_ms,mean_cycles,median_ms,std_ms,median_cycles,min_ms,max_ms,ops_s
 * stderr: '#meta algo=.. pk=.. sk=.. sigmax=.. sig=..' or '#meta algo=.. status=..' per spec (to_customer_form.py)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <math.h>
#if defined(SIG_LIBOQS)
#include <oqs/oqs.h>
#elif defined(SIG_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#else
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#endif

/* ---------- cycle counter ---------- */
#ifdef __linux__
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
static int g_perf = -1;
static void cyc_init(void){
    struct perf_event_attr a; memset(&a,0,sizeof a);
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof a; a.config=PERF_COUNT_HW_CPU_CYCLES;
    a.disabled=0; a.exclude_kernel=1; a.exclude_hv=1;
    g_perf=syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(g_perf==-1) fprintf(stderr,"[i] perf cycles unavailable (try: sudo sysctl kernel.perf_event_paranoid=1) - cycles=0\n");
}
static uint64_t cyc(void){ uint64_t v=0; if(g_perf!=-1 && read(g_perf,&v,sizeof v)!=sizeof v) v=0; return v; }
#elif defined(__APPLE__) && defined(__aarch64__)
/* Apple Silicon cycle counter via the private kperf framework.
 * Same technique as SQIsign's bench_macos.h, based on Dougall Johnson's
 * public-domain/MIT M1 counter code (github.com/dougallj). Needs root;
 * private API, may break on future macOS versions - fails soft to cycles=0. */
#include <dlfcn.h>
static int (*kpc_force_all_ctrs_set)(int);
static int (*kpc_set_counting)(uint32_t);
static int (*kpc_set_thread_counting)(uint32_t);
static int (*kpc_set_config)(uint32_t, void *);
static int (*kpc_get_thread_counters)(int, unsigned int, void *);
#define KPC_MASK 3u            /* (1<<KPC_CLASS_FIXED)|(1<<KPC_CLASS_CONFIGURABLE) */
#define CPMU_CORE_CYCLE 0x02
#define CFGWORD_EL0A64EN_MASK 0x20000
static uint64_t g_kpc_cfg[10], g_kpc_ctrs[10];
static int g_kperf_ok = 0;
static void cyc_init(void){
    void *kperf = dlopen(
        "/System/Library/PrivateFrameworks/kperf.framework/Versions/A/kperf",
        RTLD_LAZY);
    if(!kperf){ fprintf(stderr,"[i] kperf framework not found - cycles=0\n"); return; }
    kpc_force_all_ctrs_set   = (int(*)(int))dlsym(kperf,"kpc_force_all_ctrs_set");
    kpc_set_counting         = (int(*)(uint32_t))dlsym(kperf,"kpc_set_counting");
    kpc_set_thread_counting  = (int(*)(uint32_t))dlsym(kperf,"kpc_set_thread_counting");
    kpc_set_config           = (int(*)(uint32_t,void*))dlsym(kperf,"kpc_set_config");
    kpc_get_thread_counters  = (int(*)(int,unsigned int,void*))dlsym(kperf,"kpc_get_thread_counters");
    if(!kpc_force_all_ctrs_set || !kpc_set_counting || !kpc_set_thread_counting ||
       !kpc_set_config || !kpc_get_thread_counters){
        fprintf(stderr,"[i] kperf symbols missing - cycles=0\n"); return;
    }
    g_kpc_cfg[0] = CPMU_CORE_CYCLE | CFGWORD_EL0A64EN_MASK;
    if(kpc_force_all_ctrs_set(1) || kpc_set_config(KPC_MASK, g_kpc_cfg) ||
       kpc_set_counting(KPC_MASK) || kpc_set_thread_counting(KPC_MASK)){
        fprintf(stderr,"[i] kperf init failed (re-run with sudo for real cycles) - cycles=0\n");
        return;
    }
    g_kperf_ok = 1;
}
static uint64_t cyc(void){
    if(!g_kperf_ok) return 0;
    if(kpc_get_thread_counters(0, 10, g_kpc_ctrs)) return 0;
    return g_kpc_ctrs[2];
}
#else
static void cyc_init(void){}
static uint64_t cyc(void){ return 0; }
#endif

static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1e3+t.tv_nsec/1e6; }
static int dcmp(const void*a,const void*b){ double x=*(const double*)a,y=*(const double*)b; return x<y?-1:x>y?1:0; }
/* time one statement: ms[i] and cy[i] get its wall time and cycles */
#define TIMED(ms_i, cy_i, stmt) do { uint64_t c0_ = cyc(); double t0_ = now_ms(); stmt; \
                                     (ms_i) = now_ms() - t0_; (cy_i) = (double)(cyc() - c0_); } while (0)

/* per-op samples -> one CSV row (mean, median, population std, min, max, ops/s; cycles as mean + median) */
static void report(const char*spec,const char*op,int n,double*ms,double*cy){
    double sum=0,csum=0,var=0;
    for(int i=0;i<n;i++){ sum+=ms[i]; csum+=cy[i]; }
    double mean=sum/n;
    for(int i=0;i<n;i++) var+=(ms[i]-mean)*(ms[i]-mean);
    qsort(ms,n,sizeof *ms,dcmp); qsort(cy,n,sizeof *cy,dcmp);
    printf("%s,%s,%d,%.6f,%llu,%.6f,%.6f,%llu,%.6f,%.6f,%.2f\n",spec,op,n,mean,(unsigned long long)(csum/n),
           n%2?ms[n/2]:(ms[n/2-1]+ms[n/2])/2,sqrt(var/n),(unsigned long long)(n%2?cy[n/2]:(cy[n/2-1]+cy[n/2])/2),
           ms[0],ms[n-1],mean>0?1e3/mean:0);
}

#if defined(SIG_LIBOQS)
/* spec = a liboqs name */
static int bench(const char *spec, int iters){
    OQS_SIG *s=OQS_SIG_new(spec);
    if(!s){ fprintf(stderr,"[-] '%s' not in this liboqs build\n",spec);
            fprintf(stderr,"#meta algo=%s status=UNSUPPORTED(not_in_this_liboqs)\n",spec); return 1; }
    unsigned char msg[64]; memset(msg,'x',sizeof msg);
    uint8_t *pk=malloc(s->length_public_key), *sk=malloc(s->length_secret_key);
    uint8_t *sig=malloc(s->length_signature), *scratch=malloc(s->length_signature);
    size_t real=s->length_signature;
    if(OQS_SIG_keypair(s,pk,sk)!=OQS_SUCCESS || OQS_SIG_sign(s,sig,&real,msg,sizeof msg,sk)!=OQS_SUCCESS){
        fprintf(stderr,"[-] keygen/sign failed for '%s'\n",spec); fprintf(stderr,"#meta algo=%s status=SIGN_FAIL\n",spec); return 1; }
    fprintf(stderr,"#meta algo=%s pk=%zu sk=%zu sigmax=%zu sig=%zu\n",spec,s->length_public_key,
            s->length_secret_key,s->length_signature,real);
    double *ms=malloc(sizeof(double)*iters), *cy=malloc(sizeof(double)*iters);
    uint8_t *pk2=malloc(s->length_public_key), *sk2=malloc(s->length_secret_key);
    for(int i=0;i<iters;i++) TIMED(ms[i],cy[i], OQS_SIG_keypair(s,pk2,sk2));
    report(spec,"keygen",iters,ms,cy);
    for(int i=0;i<iters;i++){ size_t sl=s->length_signature; TIMED(ms[i],cy[i], OQS_SIG_sign(s,scratch,&sl,msg,sizeof msg,sk)); }
    report(spec,"sign",iters,ms,cy);
    int vfail=0;
    for(int i=0;i<iters;i++) TIMED(ms[i],cy[i], if(OQS_SIG_verify(s,msg,sizeof msg,sig,real,pk)!=OQS_SUCCESS) vfail++);
    report(spec,"verify",iters,ms,cy);
    if(vfail){ fprintf(stderr,"[-] %s: %d/%d verifies FAILED - verify timings invalid\n",spec,vfail,iters);
               fprintf(stderr,"#meta algo=%s status=VERIFY_FAIL\n",spec); }
    free(ms); free(cy); free(pk); free(sk); free(pk2); free(sk2); free(sig); free(scratch); OQS_SIG_free(s);
    return 0;
}
#elif defined(SIG_WOLFSSL)
/* spec = the Stage 1 name. RSA and ECDSA sign a SHA-256 digest (wc_SignatureGenerate), as EVP does. */
static WC_RNG rng;
enum { W_RSA, W_ECC, W_ED, W_MLDSA, W_FALCON, W_SLH };
typedef struct {
    int kind, param;  /* RSA bits | ML-DSA level | Falcon level | SlhDsaParam */
    union { RsaKey rsa; ecc_key ecc; ed25519_key ed; wc_MlDsaKey ml; falcon_key fa; SlhDsaKey slh; } k;
} wkey;
static const struct { const char *name; int kind, param, sig; } W_ALGS[] = {
    {"RSA-2048", W_RSA, 2048, 256}, {"RSA-3072", W_RSA, 3072, 384}, {"ECDSA-P256", W_ECC, 32, 72}, {"Ed25519", W_ED, 0, 64},
    {"ML-DSA-44", W_MLDSA, WC_ML_DSA_44, 0}, {"ML-DSA-65", W_MLDSA, WC_ML_DSA_65, 0}, {"ML-DSA-87", W_MLDSA, WC_ML_DSA_87, 0},
#ifdef HAVE_FALCON
    {"Falcon-512", W_FALCON, 1, FALCON_LEVEL1_SIG_SIZE}, {"Falcon-1024", W_FALCON, 5, FALCON_LEVEL5_SIG_SIZE},
#endif
    {"SLH-DSA-SHAKE-128s", W_SLH, SLHDSA_SHAKE128S, 7856}, {"SLH-DSA-SHAKE-128f", W_SLH, SLHDSA_SHAKE128F, 17088},
    {"SLH-DSA-SHAKE-192s", W_SLH, SLHDSA_SHAKE192S, 16224}, {"SLH-DSA-SHAKE-192f", W_SLH, SLHDSA_SHAKE192F, 35664},
    {"SLH-DSA-SHAKE-256s", W_SLH, SLHDSA_SHAKE256S, 29792}, {"SLH-DSA-SHAKE-256f", W_SLH, SLHDSA_SHAKE256F, 49856},
#ifdef WOLFSSL_SLHDSA_SHA2
    {"SLH-DSA-SHA2-128s", W_SLH, SLHDSA_SHA2_128S, 7856}, {"SLH-DSA-SHA2-128f", W_SLH, SLHDSA_SHA2_128F, 17088},
    {"SLH-DSA-SHA2-192s", W_SLH, SLHDSA_SHA2_192S, 16224}, {"SLH-DSA-SHA2-192f", W_SLH, SLHDSA_SHA2_192F, 35664},
    {"SLH-DSA-SHA2-256s", W_SLH, SLHDSA_SHA2_256S, 29792}, {"SLH-DSA-SHA2-256f", W_SLH, SLHDSA_SHA2_256F, 49856},
#endif
};
static int w_init(wkey *w){  /* an empty key object of the right type and parameter set */
    switch(w->kind){
    case W_RSA: if(wc_InitRsaKey(&w->k.rsa,NULL)) return -1;
#ifdef WC_RSA_BLINDING
                return wc_RsaSetRNG(&w->k.rsa,&rng);
#else
                return 0;
#endif
    case W_ECC: return wc_ecc_init(&w->k.ecc);
    case W_ED:  return wc_ed25519_init(&w->k.ed);
    case W_MLDSA: return wc_MlDsaKey_Init(&w->k.ml,NULL,INVALID_DEVID) || wc_MlDsaKey_SetParams(&w->k.ml,(byte)w->param);
#ifdef HAVE_FALCON
    case W_FALCON: return wc_falcon_init(&w->k.fa) || wc_falcon_set_level(&w->k.fa,(byte)w->param);
#endif
    case W_SLH: return wc_SlhDsaKey_Init(&w->k.slh,(enum SlhDsaParam)w->param,NULL,INVALID_DEVID);
    }
    return -1;
}
static int w_keygen(wkey *w){
    switch(w->kind){
    case W_RSA: return wc_MakeRsaKey(&w->k.rsa,w->param,WC_RSA_EXPONENT,&rng);
    case W_ECC: return wc_ecc_make_key_ex(&rng,w->param,&w->k.ecc,ECC_SECP256R1);
    case W_ED:  return wc_ed25519_make_key(&rng,ED25519_KEY_SIZE,&w->k.ed);
    case W_MLDSA: return wc_MlDsaKey_MakeKey(&w->k.ml,&rng);
#ifdef HAVE_FALCON
    case W_FALCON: return wc_falcon_make_key(&w->k.fa,&rng);
#endif
    case W_SLH: return wc_SlhDsaKey_MakeKey(&w->k.slh,&rng);
    }
    return -1;
}
static int w_sign(wkey *w,const byte*m,word32 ml,byte*sig,word32*sl){
    switch(w->kind){
    /* _ex(..., 0): no verify-after-sign (wc_SignatureGenerate's fault check), as EVP_DigestSign does none */
    case W_RSA: return wc_SignatureGenerate_ex(WC_HASH_TYPE_SHA256,WC_SIGNATURE_TYPE_RSA_W_ENC,m,ml,sig,sl,&w->k.rsa,sizeof w->k.rsa,&rng,0);
    case W_ECC: return wc_SignatureGenerate_ex(WC_HASH_TYPE_SHA256,WC_SIGNATURE_TYPE_ECC,m,ml,sig,sl,&w->k.ecc,sizeof w->k.ecc,&rng,0);
    case W_ED:  return wc_ed25519_sign_msg(m,ml,sig,sl,&w->k.ed);
    case W_MLDSA: return wc_MlDsaKey_SignCtx(&w->k.ml,NULL,0,sig,sl,m,ml,&rng);
#ifdef HAVE_FALCON
    case W_FALCON: return wc_falcon_sign_msg(m,ml,sig,sl,&w->k.fa,&rng);
#endif
    case W_SLH: return wc_SlhDsaKey_Sign(&w->k.slh,NULL,0,m,ml,sig,sl,&rng);
    }
    return -1;
}
static int w_verify(wkey *w,const byte*m,word32 ml,const byte*sig,word32 sl){  /* 1 = valid */
    int res=0;
    switch(w->kind){
    case W_RSA: return wc_SignatureVerify(WC_HASH_TYPE_SHA256,WC_SIGNATURE_TYPE_RSA_W_ENC,m,ml,sig,sl,&w->k.rsa,sizeof w->k.rsa)==0;
    case W_ECC: return wc_SignatureVerify(WC_HASH_TYPE_SHA256,WC_SIGNATURE_TYPE_ECC,m,ml,sig,sl,&w->k.ecc,sizeof w->k.ecc)==0;
    case W_ED:  return wc_ed25519_verify_msg(sig,sl,m,ml,&res,&w->k.ed)==0 && res==1;
    case W_MLDSA: return wc_MlDsaKey_VerifyCtx(&w->k.ml,sig,sl,NULL,0,m,ml,&res)==0 && res==1;
#ifdef HAVE_FALCON
    case W_FALCON: return wc_falcon_verify_msg(sig,sl,m,ml,&res,&w->k.fa)==0 && res==1;
#endif
    case W_SLH: return wc_SlhDsaKey_Verify(&w->k.slh,NULL,0,m,ml,sig,sl)==0;
    }
    return 0;
}
static void w_free(wkey *w){
    switch(w->kind){
    case W_RSA: wc_FreeRsaKey(&w->k.rsa); break;
    case W_ECC: wc_ecc_free(&w->k.ecc); break;
    case W_ED:  wc_ed25519_free(&w->k.ed); break;
    case W_MLDSA: wc_MlDsaKey_Free(&w->k.ml); break;
#ifdef HAVE_FALCON
    case W_FALCON: wc_falcon_free(&w->k.fa); break;
#endif
    case W_SLH: wc_SlhDsaKey_Free(&w->k.slh); break;
    }
}
static void w_sizes(wkey *w,int sigmax,size_t*pk,size_t*sk,size_t*smax){
    int p=0,s=0,g=sigmax;
    switch(w->kind){
    case W_RSA: p=w->param/8; s=wc_RsaKeyToDer(&w->k.rsa,NULL,0); break;  /* modulus; PKCS#1 DER private key */
    case W_ECC: p=2*w->param; s=w->param; break;     /* point x || y (as the Pico reports); private scalar */
    case W_ED:  p=s=32; break;
    case W_MLDSA: wc_MlDsaKey_GetPubLen(&w->k.ml,&p); wc_MlDsaKey_GetSigLen(&w->k.ml,&g);  /* FIPS 204 sk size (GetPrivLen adds pk) */
                  s=w->param==WC_ML_DSA_44?WC_MLDSA_44_KEY_SIZE:w->param==WC_ML_DSA_65?WC_MLDSA_65_KEY_SIZE:WC_MLDSA_87_KEY_SIZE; break;
#ifdef HAVE_FALCON
    case W_FALCON: p=w->param==1?FALCON_LEVEL1_PUB_KEY_SIZE:FALCON_LEVEL5_PUB_KEY_SIZE;
                   s=w->param==1?FALCON_LEVEL1_KEY_SIZE:FALCON_LEVEL5_KEY_SIZE; break;
#endif
    case W_SLH: { int n=sigmax==7856||sigmax==17088?16:sigmax==16224||sigmax==35664?24:32; p=2*n; s=4*n; break; }
    }
    *pk=(size_t)p; *sk=(size_t)s; *smax=(size_t)g;
}
static int bench(const char *spec, int iters){
    static wkey w, tmp;
    static byte sig[65536], scratch[65536];
    int a=-1;
    for(int i=0;i<(int)(sizeof W_ALGS/sizeof *W_ALGS);i++) if(!strcmp(spec,W_ALGS[i].name)) a=i;
    memset(&w,0,sizeof w);
    if(a>=0){ w.kind=W_ALGS[a].kind; w.param=W_ALGS[a].param; }
    if(a<0 || w_init(&w) || w_keygen(&w)){
        fprintf(stderr,"[-] '%s' not in this wolfSSL build\n",spec);
        fprintf(stderr,"#meta algo=%s status=UNSUPPORTED(not_in_this_wolfSSL_build)\n",spec); return 1; }
    byte msg[64]; memset(msg,'x',sizeof msg);
    word32 real=sizeof sig;
    if(w_sign(&w,msg,sizeof msg,sig,&real)){
        fprintf(stderr,"[-] sign failed for '%s'\n",spec); fprintf(stderr,"#meta algo=%s status=SIGN_FAIL\n",spec); return 1; }
    size_t pk,sk,smax; w_sizes(&w,W_ALGS[a].sig,&pk,&sk,&smax);
    fprintf(stderr,"#meta algo=%s pk=%zu sk=%zu sigmax=%zu sig=%u\n",spec,pk,sk,smax,real);
    double *ms=malloc(sizeof(double)*iters), *cy=malloc(sizeof(double)*iters);
    for(int i=0;i<iters;i++){ tmp.kind=w.kind; tmp.param=w.param; w_init(&tmp);   /* key object: outside the timer */
        TIMED(ms[i],cy[i], w_keygen(&tmp)); w_free(&tmp); }
    report(spec,"keygen",iters,ms,cy);
    for(int i=0;i<iters;i++){ word32 sl=sizeof scratch; TIMED(ms[i],cy[i], w_sign(&w,msg,sizeof msg,scratch,&sl)); }
    report(spec,"sign",iters,ms,cy);
    int vfail=0;
    for(int i=0;i<iters;i++) TIMED(ms[i],cy[i], if(!w_verify(&w,msg,sizeof msg,sig,real)) vfail++);
    report(spec,"verify",iters,ms,cy);
    if(vfail){ fprintf(stderr,"[-] %s: %d/%d verifies FAILED - verify timings invalid\n",spec,vfail,iters);
               fprintf(stderr,"#meta algo=%s status=VERIFY_FAIL\n",spec); }
    free(ms); free(cy); w_free(&w);
    return 0;
}
#else
/* spec = "RSA:3072" | "EC:P-256" | "<algname>": its keygen context, set up once (outside the timer) */
static EVP_PKEY_CTX *keygen_ctx(const char *spec){
    char name[64]; const char *arg=NULL;
    const char *c=strchr(spec,':');
    if(c){ size_t l=(size_t)(c-spec); if(l>=sizeof name)l=sizeof name-1; memcpy(name,spec,l); name[l]=0; arg=c+1; }
    else { strncpy(name,spec,sizeof name-1); name[sizeof name-1]=0; }
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_name(NULL,name,NULL);
    if(!ctx) return NULL;
    if(EVP_PKEY_keygen_init(ctx)<=0){ EVP_PKEY_CTX_free(ctx); return NULL; }
    OSSL_PARAM p[2]; int np=0; unsigned int bits=0;
    if(arg && strcmp(name,"RSA")==0){ bits=(unsigned)atoi(arg); p[np++]=OSSL_PARAM_construct_uint("bits",&bits); }
    else if(arg && strcmp(name,"EC")==0){ p[np++]=OSSL_PARAM_construct_utf8_string("group",(char*)arg,0); }
    p[np]=OSSL_PARAM_construct_end();
    if(np) EVP_PKEY_CTX_set_params(ctx,p);
    return ctx;
}

static int bench(const char *spec, int iters){
    int classical = (strncmp(spec,"RSA",3)==0 || strncmp(spec,"EC:",3)==0 || strcmp(spec,"EC")==0);
    const char *md = classical ? "SHA256" : NULL;   /* RSA/ECDSA prehash; PQC + EdDSA are pure */

    EVP_PKEY_CTX *kc=keygen_ctx(spec); EVP_PKEY *pk=NULL;
    if(!kc || EVP_PKEY_generate(kc,&pk)<=0){ fprintf(stderr,"[-] keygen failed for '%s' (unknown algorithm? provider not loaded?)\n",spec);
             fprintf(stderr,"#meta algo=%s status=UNSUPPORTED(not_in_this_OpenSSL/oqsprovider)\n",spec); EVP_PKEY_CTX_free(kc); return 1; }

    unsigned char msg[64]; memset(msg,'x',sizeof msg);
    EVP_MD_CTX *mc=EVP_MD_CTX_new();
    size_t siglen=0;
    if(EVP_DigestSignInit_ex(mc,NULL,md,NULL,NULL,pk,NULL)<=0 ||
       EVP_DigestSign(mc,NULL,&siglen,msg,sizeof msg)<=0){ fprintf(stderr,"[-] sign-init failed for '%s'\n",spec);
        fprintf(stderr,"#meta algo=%s status=VERIFY_ONLY_OR_NO_SIGN\n",spec); return 1; }
    unsigned char *sig=malloc(siglen); size_t real=siglen;
    EVP_MD_CTX_reset(mc); EVP_DigestSignInit_ex(mc,NULL,md,NULL,NULL,pk,NULL);
    EVP_DigestSign(mc,sig,&real,msg,sizeof msg);
    /* scratch buffer for the sign loop - keeps sig/real intact for the verify
     * loop (ECDSA DER sigs vary in length; overwriting sig but keeping the old
     * `real` makes verify fail instantly and fakes a ~20x-too-fast verify). */
    unsigned char *scratch=malloc(siglen);

    /* Key/signature sizes -> stderr. pk/sk: raw key bytes where the provider exposes them (Ed25519 + all
     * PQC algs). ECDSA: the point x || y (2 x field bytes, as the Pico reports) and the private scalar. RSA:
     * the modulus and the PKCS#1 DER private key (n, e, d, p, q, CRT values). sig: the measured signature
     * length (DER for ECDSA, so ~71 B rather than the raw 64). */
    {
        size_t publen=0, privlen=0, nb=(size_t)((EVP_PKEY_get_bits(pk)+7)/8);
        if(EVP_PKEY_get_raw_public_key(pk,NULL,&publen)<=0)  publen=0;
        if(EVP_PKEY_get_raw_private_key(pk,NULL,&privlen)<=0) privlen=0;
        if(EVP_PKEY_is_a(pk,"EC")){ publen=2*nb; privlen=nb; }
        else if(EVP_PKEY_is_a(pk,"RSA")){ int d=i2d_PrivateKey(pk,NULL); publen=nb; privlen=d>0?(size_t)d:nb; }
        if(!publen)  publen=nb;
        if(!privlen) privlen=nb;
        fprintf(stderr,"#meta algo=%s pk=%zu sk=%zu sigmax=%d sig=%zu\n",spec,publen,privlen,EVP_PKEY_get_size(pk),real);
    }

    double *ms=malloc(sizeof(double)*iters), *cy=malloc(sizeof(double)*iters);
    double *sms=malloc(sizeof(double)*iters), *scy=malloc(sizeof(double)*iters);   /* sign setup */
    double *vms=malloc(sizeof(double)*iters), *vcy=malloc(sizeof(double)*iters);   /* verify setup */
    for(int i=0;i<iters;i++){ EVP_PKEY *tmp=NULL; TIMED(ms[i],cy[i], EVP_PKEY_generate(kc,&tmp)); EVP_PKEY_free(tmp); }
    report(spec,"keygen",iters,ms,cy);
    for(int i=0;i<iters;i++){ size_t sl=siglen;
        TIMED(sms[i],scy[i], EVP_MD_CTX_reset(mc); EVP_DigestSignInit_ex(mc,NULL,md,NULL,NULL,pk,NULL));
        TIMED(ms[i],cy[i], EVP_DigestSign(mc,scratch,&sl,msg,sizeof msg)); }
    report(spec,"sign",iters,ms,cy);
    int vfail=0;
    for(int i=0;i<iters;i++){
        TIMED(vms[i],vcy[i], EVP_MD_CTX_reset(mc); EVP_DigestVerifyInit_ex(mc,NULL,md,NULL,NULL,pk,NULL));
        TIMED(ms[i],cy[i], if(EVP_DigestVerify(mc,sig,real,msg,sizeof msg)!=1) vfail++); }
    report(spec,"verify",iters,ms,cy);
    report(spec,"sign_setup",iters,sms,scy);
    report(spec,"verify_setup",iters,vms,vcy);
    if(vfail){ fprintf(stderr,"[-] %s: %d/%d verifies FAILED - verify timings invalid\n",spec,vfail,iters);
               fprintf(stderr,"#meta algo=%s status=VERIFY_FAIL\n",spec); }

    free(ms); free(cy); free(sms); free(scy); free(vms); free(vcy); free(sig); free(scratch);
    EVP_MD_CTX_free(mc); EVP_PKEY_free(pk); EVP_PKEY_CTX_free(kc);
    return 0;
}
#endif

int main(int argc,char**argv){
#if defined(SIG_LIBOQS)
    OQS_init();
#elif defined(SIG_WOLFSSL)
    wolfCrypt_Init();
    if(wc_InitRng(&rng)){ fprintf(stderr,"[-] wc_InitRng failed\n"); return 1; }
#else
    OSSL_PROVIDER_load(NULL,"default"); OSSL_PROVIDER_load(NULL,"oqsprovider");
#endif
    if(argc<3){ fprintf(stderr,"usage: %s <iterations> <spec> [spec...]\n",argv[0]); return 1; }
    cyc_init();
    int iters=atoi(argv[1]);
    printf("algo,op,n,mean_ms,mean_cycles,median_ms,std_ms,median_cycles,min_ms,max_ms,ops_s\n");
    for(int a=2;a<argc;a++) bench(argv[a],iters);
    return 0;
}
