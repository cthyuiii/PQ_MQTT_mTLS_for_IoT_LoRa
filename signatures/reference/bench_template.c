/*
 * bench_template.c - generic NIST API signature benchmark.
 *
 * Every NIST PQC signature submission exposes the same C API in api.h:
 *     - CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES
 *     - int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
 *     - int crypto_sign(unsigned char *sm, unsigned long long *smlen,
 *                       const unsigned char *m, unsigned long long mlen,
 *                       const unsigned char *sk)
 *     - int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
 *                            const unsigned char *sm, unsigned long long smlen,
 *                            const unsigned char *pk)
 *
 * This program is compiled WITH each algorithm's reference .c files, so
 * the symbols above resolve against that algorithm's implementation.  No
 * shared library is needed.
 *
 * Output goes to stdout as CSV (label,iteration,latency_us,cycles) so the Python
 * runner can aggregate it into sig_summary_reference.csv. cycles = CPU cycles in user space from
 * perf_event_open on Linux (the Pi; needs kernel.perf_event_paranoid <= 2, as sig_speed.c), 0 elsewhere.
 *
 * Usage:
 *     ./bench <friendly_label> <iterations> [warmup]
 *
 * Example:
 *     ./bench HAWK-512 200 5
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "api.h"

#define MESSAGE_LEN 64
#define DEFAULT_WARMUP 5

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

#ifdef __linux__
#include <sys/syscall.h>
#include <linux/perf_event.h>
static int g_perf = -1;
static void cyc_init(void) {
    struct perf_event_attr a; memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE; a.size = sizeof a; a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1; a.exclude_hv = 1;
    g_perf = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    if (g_perf == -1) fprintf(stderr, "[i] perf cycles unavailable (sudo sysctl kernel.perf_event_paranoid=1) - cycles=0\n");
}
static unsigned long long cyc(void) {
    unsigned long long v = 0;
    if (g_perf != -1 && read(g_perf, &v, sizeof v) != sizeof v) v = 0;
    return v;
}
#else
static void cyc_init(void) {}
static unsigned long long cyc(void) { return 0; }
#endif

/* ---------------------------------------------------------------------------
 * randombytes() - NIST KAT-API compatible RNG, reads from /dev/urandom.
 *
 * NIST submissions expect this symbol (declared in their api.h or rng.h):
 *     int randombytes(unsigned char *x, unsigned long long xlen);
 *
 * The reference impls normally get it from generator/rng.c (an AES-CTR RNG
 * seeded for KAT reproducibility), but we exclude that file because it
 * ships alongside PQCgenKAT_sign.c with its own main(), which would conflict
 * with this file's main().  For benchmarking we don't need a deterministic
 * RNG, just any RNG that fills the buffer.  /dev/urandom is portable across
 * macOS + Linux with zero extra dependencies.
 * ---------------------------------------------------------------------- */
int randombytes(unsigned char *x, unsigned long long xlen) {
    static int fd = -1;
    if (fd < 0) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
    }
    unsigned long long off = 0;
    while (off < xlen) {
        ssize_t n = read(fd, x + off, (size_t)(xlen - off));
        if (n <= 0) return -1;
        off += (unsigned long long)n;
    }
    return 0;
}

/* Some submissions call randombytes_init() for NIST KAT seeding.
 * Provide a no-op stub so the linker is happy. */
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength) {
    (void)entropy_input;
    (void)personalization_string;
    (void)security_strength;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <friendly_label> <iterations> [warmup]\n"
                "Outputs CSV: label,iteration,latency_us\n",
                argv[0]);
        return 1;
    }
    const char *label = argv[1];
    int iters = atoi(argv[2]);
    int warmup = (argc >= 4) ? atoi(argv[3]) : DEFAULT_WARMUP;
    if (iters <= 0) { fprintf(stderr, "iterations must be > 0\n"); return 1; }

    unsigned char *pk = (unsigned char *)malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = (unsigned char *)malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char *sm = (unsigned char *)malloc(CRYPTO_BYTES + MESSAGE_LEN);
    unsigned char *m_out = (unsigned char *)malloc(CRYPTO_BYTES + MESSAGE_LEN);
    if (!pk || !sk || !sm || !m_out) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    /* 64-byte fixed message (matches the Cython benchmark for fairness). */
    const unsigned char message[MESSAGE_LEN] =
        "IoT-PQC reference benchmark message - 64 bytes long for FIPS te";
    unsigned long long sm_len = 0;
    unsigned long long m_len = 0;

    /* One-time keypair, not benchmarked. */
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "crypto_sign_keypair failed\n");
        return 2;
    }

    /* Emit CSV header to stdout. */
    cyc_init();
    printf("label,iteration,latency_us,cycles\n");

    /* ----- Keygen benchmark ----- */
    /* Re-generates a fresh keypair each iteration; the final pk/sk left in the
     * buffers is a valid pair, so the sign/verify loops below still work. */
    for (int i = 0; i < iters + warmup; i++) {
        unsigned long long c1 = cyc();
        double t1 = now_us();
        int rc = crypto_sign_keypair(pk, sk);
        double t2 = now_us();
        unsigned long long c2 = cyc();
        if (rc != 0) {
            fprintf(stderr, "crypto_sign_keypair rc=%d at iter %d\n", rc, i);
            return 2;
        }
        if (i >= warmup) {
            printf("%s keygen,%d,%.3f,%llu\n", label, i - warmup + 1, t2 - t1, c2 - c1);
        }
    }

    /* ----- Sign benchmark ----- */
    for (int i = 0; i < iters + warmup; i++) {
        sm_len = CRYPTO_BYTES + MESSAGE_LEN;
        unsigned long long c1 = cyc();
        double t1 = now_us();
        int rc = crypto_sign(sm, &sm_len, message, MESSAGE_LEN, sk);
        double t2 = now_us();
        unsigned long long c2 = cyc();
        if (rc != 0) {
            fprintf(stderr, "crypto_sign rc=%d at iter %d\n", rc, i);
            return 3;
        }
        if (i >= warmup) {
            printf("%s sign,%d,%.3f,%llu\n", label, i - warmup + 1, t2 - t1, c2 - c1);
        }
    }

    /* ----- Verify benchmark - reuse the last signature ----- */
    for (int i = 0; i < iters + warmup; i++) {
        m_len = CRYPTO_BYTES + MESSAGE_LEN;
        unsigned long long c1 = cyc();
        double t1 = now_us();
        int rc = crypto_sign_open(m_out, &m_len, sm, sm_len, pk);
        double t2 = now_us();
        unsigned long long c2 = cyc();
        if (rc != 0) {
            fprintf(stderr, "crypto_sign_open rc=%d at iter %d\n", rc, i);
            return 4;
        }
        if (i >= warmup) {
            printf("%s verify,%d,%.3f,%llu\n", label, i - warmup + 1, t2 - t1, c2 - c1);
        }
    }

    /* Sizes printed last so the runner can capture pk/sig/sk bytes too.
     * Prefixed with '#' so they don't pollute the timing CSV. */
    fprintf(stderr,
            "#meta label=%s pk=%d sk=%d sig=%d\n",
            label,
            (int)CRYPTO_PUBLICKEYBYTES,
            (int)CRYPTO_SECRETKEYBYTES,
            (int)CRYPTO_BYTES);

    free(pk); free(sk); free(sm); free(m_out);
    return 0;
}
