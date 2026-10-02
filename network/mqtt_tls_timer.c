/* mqtt_tls_timer.c - Stage 2 connection timer: MQTT 3.1.1 CONNECT to a real broker
 * over plain TCP (the reference), TLS 1.3, or mutual TLS. Per iteration it times
 *   TCP connect | TLS handshake (ClientHello..Finished) | MQTT CONNECT..CONNACK
 * and counts the bytes the client moved on the socket in each direction during
 * the handshake and during the MQTT exchange. One source, two TLS libraries:
 *
 *   OpenSSL: cc -O2 mqtt_tls_timer.c -o mqtt_tls_timer -lssl -lcrypto
 *            (macOS: add -I/-L "$(brew --prefix openssl@3)"/{include,lib})
 *   wolfSSL: see build_wolfssl.sh (-DUSE_WOLFSSL -lwolfssl)
 *
 *   ./mqtt_tls_timer <host> <port> <iters> <warmup> [CAfile [cert key]]
 *     no CAfile -> plain MQTT, CAfile -> TLS (server auth), + cert key -> mTLS
 *     GROUP env fixes the key exchange (default X25519MLKEM768); SUITE picks the TLS 1.3 cipher
 *     suite (e.g. TLS_AES_128_GCM_SHA256), default = library default.
 *
 * Full pipeline (MSGS > 0): after CONNACK the client SUBSCRIBEs to its own topic and sends MSGS
 * telemetry PUBLISHes (QoS 0). Each payload (PAYLOAD bytes, default 51) is protected end to end by
 * AEAD = none | lorawan10 | lorawan11 | aes128gcm | aes256gcm | ascon (app_aead.c) inside the TLS
 * session, travels through the broker, comes back, and is verified + decrypted:
 *   PQ handshake -> AES/LoRaWAN/Ascon payload protection -> MQTT broker -> subscriber.
 * DOWN=1 sends downlink frames (MHDR 0x60, Dir = 1: what a network server sends a device) instead of uplinks.
 *
 * Payloads are a readable reading ({"seq":N,...} padded to PAYLOAD bytes) on topic pqc/pipe/<pid>.
 * APP_KEYS (128 hex chars: 32 B app key, 16 B + 16 B network keys) replaces the per-process random keys,
 * so another process holding the same keys can decrypt (mqtt_bench.py --watch sets it).
 *
 * Watch mode (SUB = topic filter, e.g. "pqc/pipe/#"): an independent subscriber on the same host / port /
 * TLS options. It prints every PUBLISH as it arrives: time, topic, bytes, FCnt, and with APP_KEYS the
 * scheme whose MIC / tag verifies plus the decrypted reading (a frame no scheme verifies is shown as
 * unprotected "none" text, or as ciphertext without keys). The topic stays scheme-free so the bytes on
 * the wire match timing runs. WATCH_NAME labels the lines. Runs until killed; keepalive 0 (Mosquitto's
 * default max_keepalive 0 allows it).
 *
 * stdout: "#lib <version>", "#suite <negotiated TLS suite>", then CSV
 *   iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B
 * and with MSGS > 0 also
 *   msg,iter,idx,seal_us,rtt_us,open_us,tx_B,rx_B      (per message; tx/rx = bytes on the socket)
 * Any failure: reason on stderr, exit 1 (the driver records it as the result).
 * mqtt_rx_B includes TLS 1.3 NewSessionTickets the broker sends after the handshake.
 *
 * KEM exchange through the broker (built with -DHAVE_LIBOQS as mqtt_kem_timer: build_timer.sh, when liboqs is installed;
 * mqtt_tls_timer itself never links liboqs, so oqs-provider inside it always uses its own):
 *   KEM=<liboqs name>, X25519 or X25519MLKEM768 (see kem_new; KEXS exchanges per connection, KEX_WARM unreported
 *   first): this client is the device. It
 *   makes a key pair, PUBLISHes the public key on pqc/kem/<pid>/pk/<KEM>, and the responder next to the broker
 *   replies on pqc/kem/<pid>/ct with ciphertext | SHA-256(shared secret) | its encapsulation time (4 B LE, us).
 *   The device decapsulates and checks the hash (key confirmation). Rows:
 *     kex,iter,idx,keygen_us,rtt_us,decaps_us,encaps_us,tx_B,rx_B    (rtt: PUBLISH of the key -> ciphertext back)
 *   KEM_RESPOND=1: the responder (mqtt_bench.py --role broker starts it on the plain listener).
 *   This is how Classic McEliece gets measured through the broker: its 261 KB - 1.36 MB public keys do not fit a
 *   TLS 1.3 key share (at most 65,535 B).
 */
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "app_aead.h"
#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#include <openssl/evp.h>   /* SHA-256 of the shared secret: key confirmation */
#include <openssl/crypto.h>  /* X25519 key exchange: OpenSSL_version, OPENSSL_cleanse */
#endif

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#ifdef HS_TIMING  // the client's crypto inside each handshake (../pico/sketches/mqtt_tls_bench/hs_timing.c, Linux + --wrap)
#include "hs_timing.h"
#endif
#else
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif
#include "wire_stats.h"   /* socket writes / reads, TCP segments */

typedef struct { int fd; uint64_t tx, rx; void *tls; uint64_t io[2]; } conn_t;  /* io = socket writes, reads */

#ifdef __APPLE__
#define TIMER_CLOCK CLOCK_UPTIME_RAW   /* ~42 ns ticks; macOS CLOCK_MONOTONIC only ticks in 1 us */
#else
#define TIMER_CLOCK CLOCK_MONOTONIC
#endif
static double now_ms(void) {
    struct timespec t; clock_gettime(TIMER_CLOCK, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}
static void die(const char *what, const char *why) { fprintf(stderr, "%s: %s\n", what, why); exit(1); }
/* why a certificate / key file didn't load: unreadable (e.g. made with sudo, or missing), else the TLS library's
 * reason. A certs/ that isn't the broker's usually shows up as a key that doesn't match its certificate. */
static const char *load_why(const char *path, const char *lib_reason) {
    static char why[768];
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(why, sizeof why, "%s: %s", path, strerror(errno)); return why; }
    fclose(f);
    snprintf(why, sizeof why, "%s: %s (a key not matching its certificate, or an algorithm this build lacks)", path,
             lib_reason ? lib_reason : "rejected");
    return why;
}

static int raw_send(conn_t *c, const void *b, int n) {  /* all n bytes: a McEliece public key is up to 1.36 MB */
    int done = 0;
    while (done < n) {
        ssize_t r; do r = send(c->fd, (const char *)b + done, n - done, 0); while (r < 0 && errno == EINTR);
        if (r <= 0) return done ? done : (int)r;
        c->tx += r; c->io[0]++; done += (int)r;
    }
    return done;
}
static int raw_recv(conn_t *c, void *b, int n) {
    ssize_t r; do r = recv(c->fd, b, n, 0); while (r < 0 && errno == EINTR);
    if (r > 0) { c->rx += r; c->io[1]++; }
    return (int)r;
}

/* ---------------------------------------------------------------- TLS layer */
#ifdef USE_WOLFSSL
static WOLFSSL_CTX *ctx;
static int group_id;
static char errbuf[WOLFSSL_MAX_ERROR_SZ];

static int cb_send(WOLFSSL *s, char *b, int n, void *c) {
    (void)s; int r = raw_send(c, b, n);
    return r >= 0 ? r : WOLFSSL_CBIO_ERR_GENERAL;
}
static int cb_recv(WOLFSSL *s, char *b, int n, void *c) {
    (void)s; int r = raw_recv(c, b, n);
    return r > 0 ? r : r == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_GENERAL;
}
static const char *tls_version(void) { static char v[64]; snprintf(v, sizeof v, "wolfSSL %s", wolfSSL_lib_version()); return v; }
static void tls_init(const char *ca, const char *cert, const char *key, const char *group, const char *suite) {
    static const struct { const char *name; int id; } groups[] = {
        {"X25519MLKEM768", WOLFSSL_X25519MLKEM768}, {"SecP256r1MLKEM768", WOLFSSL_SECP256R1MLKEM768},
        {"MLKEM768", WOLFSSL_ML_KEM_768}, {"X25519", WOLFSSL_ECC_X25519}, {"P-256", WOLFSSL_ECC_SECP256R1},
    };
    for (size_t i = 0; i < sizeof groups / sizeof *groups; i++)
        if (strcmp(group, groups[i].name) == 0) group_id = groups[i].id;
    if (!group_id) die("unsupported group", group);
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (wolfSSL_CTX_load_verify_locations(ctx, ca, NULL) != WOLFSSL_SUCCESS) die("cannot load CA cert", load_why(ca, "wolfSSL rejected it"));
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (cert && wolfSSL_CTX_use_certificate_file(ctx, cert, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        die("cannot load client certificate", load_why(cert, "wolfSSL rejected it"));
    if (cert && wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        die("cannot load client key", load_why(key, "wolfSSL rejected it"));
    wolfSSL_CTX_SetIORecv(ctx, cb_recv);
    wolfSSL_CTX_SetIOSend(ctx, cb_send);
    if (suite && wolfSSL_CTX_set_cipher_list(ctx, suite) != WOLFSSL_SUCCESS) die("unsupported suite", suite);
}
static const char *tls_cipher(conn_t *c) { return wolfSSL_get_cipher_name(c->tls); }
static const char *tls_err(conn_t *c, int r) {
    return wolfSSL_ERR_error_string(wolfSSL_get_error(c->tls, r), errbuf);
}
static int tls_connect(conn_t *c) {
    WOLFSSL *s = wolfSSL_new(ctx); c->tls = s;
    wolfSSL_SetIOReadCtx(s, c); wolfSSL_SetIOWriteCtx(s, c);
    if (wolfSSL_set_groups(s, &group_id, 1) != WOLFSSL_SUCCESS || wolfSSL_UseKeyShare(s, group_id) != WOLFSSL_SUCCESS)
        die("group not usable by this wolfSSL build", "");
    int r = wolfSSL_connect(s);
    return r == WOLFSSL_SUCCESS ? 0 : r;
}
static int tls_write(conn_t *c, const void *b, int n) { return wolfSSL_write(c->tls, b, n); }
static int tls_read(conn_t *c, void *b, int n) { return wolfSSL_read(c->tls, b, n); }
static void tls_close(conn_t *c) { wolfSSL_shutdown(c->tls); wolfSSL_free(c->tls); }
#else
static SSL_CTX *ctx;

static const char *tls_version(void) { return OpenSSL_version(OPENSSL_VERSION); }
static void tls_init(const char *ca, const char *cert, const char *key, const char *group, const char *suite) {
    /* oqsprovider (best effort) verifies Falcon/MAYO/SNOVA certs; set OPENSSL_MODULES if needed. */
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "oqsprovider");
    ERR_clear_error();
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_set1_groups_list(ctx, group) != 1) die("unsupported group", group);
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        die("cannot load CA cert", load_why(ca, ERR_reason_error_string(ERR_peek_last_error())));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (cert && SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1)
        die("cannot load client certificate", load_why(cert, ERR_reason_error_string(ERR_peek_last_error())));
    if (cert && SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
        die("cannot load client key", load_why(key, ERR_reason_error_string(ERR_peek_last_error())));
    if (suite && SSL_CTX_set_ciphersuites(ctx, suite) != 1) die("unsupported suite", suite);
}
static const char *tls_cipher(conn_t *c) { return SSL_get_cipher_name(c->tls); }
static const char *tls_err(conn_t *c, int r) {
    (void)r;
    long v = SSL_get_verify_result(c->tls);
    if (v != X509_V_OK) return X509_verify_cert_error_string(v);
    unsigned long e = ERR_peek_last_error();
    return e ? ERR_reason_error_string(e) : "connection closed by peer";
}
static void sync_bytes(conn_t *c) {
    c->tx = BIO_number_written(SSL_get_wbio(c->tls));  /* socket-BIO counters = bytes on the wire */
    c->rx = BIO_number_read(SSL_get_rbio(c->tls));
}
static int tls_connect(conn_t *c) {
    SSL *s = SSL_new(ctx); c->tls = s;
    SSL_set_fd(s, c->fd);
    count_socket_io(SSL_get_rbio(s), c->io);
    int r = SSL_connect(s);
    sync_bytes(c);
    return r == 1 ? 0 : r;
}
static int tls_write(conn_t *c, const void *b, int n) { int r = SSL_write(c->tls, b, n); sync_bytes(c); return r; }
static int tls_read(conn_t *c, void *b, int n) { int r = SSL_read(c->tls, b, n); sync_bytes(c); return r; }
static void tls_close(conn_t *c) { SSL_shutdown(c->tls); SSL_free(c->tls); }
#endif

/* ---------------------------------------------------------------- MQTT */
static int io_write(conn_t *c, const void *b, int n) { return c->tls ? tls_write(c, b, n) : raw_send(c, b, n); }
static int io_read_n(conn_t *c, unsigned char *b, int n) {
    for (int got = 0, r; got < n; got += r)
        if ((r = c->tls ? tls_read(c, b + got, n - got) : raw_recv(c, b + got, n - got)) <= 0) return r;
    return n;
}
/* one MQTT packet: returns the body length, *type = first byte; -1 on error */
static int read_packet(conn_t *c, unsigned char *type, unsigned char *body, int cap) {
    int len = 0, shift = 0;
    unsigned char b;
    if (io_read_n(c, type, 1) != 1) return -1;
    do {
        if (io_read_n(c, &b, 1) != 1 || shift > 21) return -1;
        len |= (b & 0x7F) << shift; shift += 7;
    } while (b & 0x80);
    return len <= cap && io_read_n(c, body, len) == len ? len : -1;
}
static int put_len(unsigned char *p, int len) {  /* MQTT variable-length integer */
    int n = 0;
    do { p[n] = len & 0x7F; len >>= 7; if (len) p[n] |= 0x80; n++; } while (len);
    return n;
}
static double now_us(void) { return now_ms() * 1e3; }
/* CONNECT, MQTT 3.1.1, clean session: "pqc-timer" with keepalive 60 s gives the same 23 bytes as before */
static int connect_packet(unsigned char *p, const char *id, int keepalive) {
    int il = (int)strlen(id), n = 0;
    p[n++] = 0x10; n += put_len(p + n, 10 + 2 + il);
    memcpy(p + n, "\0\4MQTT\4\2", 8); n += 8;
    p[n++] = keepalive >> 8; p[n++] = keepalive & 0xFF;
    p[n++] = il >> 8; p[n++] = il & 0xFF; memcpy(p + n, id, il);
    return n + il;
}
static void subscribe(conn_t *c, const char *filter) {  /* QoS 0, packet id 1, waits for SUBACK */
    static unsigned char pkt[512], body[64];
    int tl = (int)strlen(filter), n = 0;
    unsigned char type;
    pkt[n++] = 0x82;
    n += put_len(pkt + n, 2 + 2 + tl + 1);
    pkt[n++] = 0; pkt[n++] = 1;
    pkt[n++] = tl >> 8; pkt[n++] = tl & 0xFF; memcpy(pkt + n, filter, tl); n += tl;
    pkt[n++] = 0;
    if (io_write(c, pkt, n) != n || read_packet(c, &type, body, sizeof body) < 0 || type != 0x90)
        die("mqtt subscribe failed", "no SUBACK");
}
/* the telemetry reading, readable and padded to the payload size, so a subscriber can show it */
static void reading(unsigned char *pt, int payload, int seq) {
    char s[64];
    int n = snprintf(s, sizeof s, "{\"seq\":%d,\"temp_c\":21.5,\"rh\":48}", seq);
    memset(pt, ' ', payload);
    memcpy(pt, s, n < payload ? n : payload);
}
static int have_keys;
static unsigned char keys[64];
static void use_shared_keys(void) {  /* APP_KEYS -> app_aead (after app_aead_init / selftest) */
    /* processes share these keys (so a watcher can decrypt): a DevAddr per process keeps their nonces apart */
    pid_t pid = getpid();
    unsigned char devaddr[4] = {pid & 0xFF, pid >> 8 & 0xFF, pid >> 16 & 0xFF, 0x26};
    if (have_keys) app_aead_set_keys(keys, keys + 32, keys + 48, devaddr);
}

/* SUBSCRIBE to `topic`, then time `msgs` protected PUBLISHes that the broker echoes back to us */
static void pipeline(conn_t *c, int iter, int msgs, int payload, const char *topic, int report, int down) {
    static unsigned char pkt[2048], body[2048], pt[1024], out[1024 + 64];
    int tl = (int)strlen(topic);
    unsigned char type;
    subscribe(c, topic);
    for (int m = 0; m < msgs; m++) {
        static int seq;  /* FCnt: runs on across connections, so no key sees one twice */
        if (++seq > 0xFFFF) die("FCnt would wrap (LoRaWAN 1.0.x rejoins first):", "fewer messages per process");
        reading(pt, payload, seq);
        double t0 = now_us();
        int fl = app_seal(down, (uint32_t)seq, pt, payload, pkt + 16);  /* frame built in place */
        double t1 = now_us();
        if (fl < 0) die("payload too large for", app_aead_label());
        unsigned char hdr[8];
        int h = 0;
        hdr[h++] = 0x30;
        h += put_len(hdr + h, 2 + tl + fl);
        hdr[h++] = tl >> 8; hdr[h++] = tl & 0xFF;
        memmove(pkt + h + tl, pkt + 16, fl);            /* fixed header | topic | frame */
        memcpy(pkt, hdr, h); memcpy(pkt + h, topic, tl);
        uint64_t tx0 = c->tx, rx0 = c->rx;
        int len;
        if (io_write(c, pkt, h + tl + fl) != h + tl + fl) die("mqtt publish failed", "write");
        do len = read_packet(c, &type, body, sizeof body);  /* skip anything that isn't our PUBLISH */
        while (len >= 0 && (type & 0xF0) != 0x30);
        double t2 = now_us();
        if (len < 0) die("mqtt publish failed", "no echo from broker");
        int off = 2 + (body[0] << 8 | body[1]);
        if (app_open(body + off, len - off, out) != payload || memcmp(out, pt, payload))
            die("payload verification failed", app_aead_label());
        double t3 = now_us();
        if (report)
            printf("msg,%d,%d,%.3f,%.3f,%.3f,%llu,%llu\n", iter, m, t1 - t0, t2 - t1, t3 - t2,
                   (unsigned long long)(c->tx - tx0), (unsigned long long)(c->rx - rx0));
    }
}

#ifdef HAVE_LIBOQS
/* PUBLISH (QoS 0) of topic + data, built in pkt -> packet length */
static int publish_packet(unsigned char *pkt, const char *topic, const unsigned char *data, size_t len) {
    int tl = (int)strlen(topic), h = 0;
    pkt[h++] = 0x30; h += put_len(pkt + h, 2 + tl + (int)len);
    pkt[h++] = tl >> 8; pkt[h++] = tl & 0xFF; memcpy(pkt + h, topic, tl);
    memcpy(pkt + h + tl, data, len);
    return h + tl + (int)len;
}
static void sha256(const unsigned char *d, size_t n, unsigned char out[32]) {
    unsigned int l; EVP_Digest(d, n, out, &l, EVP_sha256(), NULL);
}

/* A KEM by name: a liboqs KEM, or X25519 / X25519MLKEM768 (the customer's TLS group) with OpenSSL's X25519. X25519
 * works as a KEM the way TLS uses it: the ciphertext is the responder's ephemeral share. The hybrid is laid out as in
 * draft-ietf-tls-ecdhe-mlkem: pk = ML-KEM-768 key | X25519 share, ct = ML-KEM ciphertext | X25519 share, shared
 * secret = ML-KEM secret | X25519 secret (the X25519 32 B always last). */
typedef struct { OQS_KEM *q; int x, level; size_t pk, sk, ct, ss; } kem_t;

static int kem_new(kem_t *k, const char *name) {
    int hy = !strcmp(name, "X25519MLKEM768");
    memset(k, 0, sizeof *k);
    k->x = hy || !strcmp(name, "X25519");
    if (hy || !k->x) {
        if (!(k->q = OQS_KEM_new(hy ? OQS_KEM_alg_ml_kem_768 : name))) return 0;
        k->pk = k->q->length_public_key; k->sk = k->q->length_secret_key;
        k->ct = k->q->length_ciphertext; k->ss = k->q->length_shared_secret; k->level = k->q->claimed_nist_level;
    }
    if (k->x) { k->pk += 32; k->sk += 32; k->ct += 32; k->ss += 32; }
    return 1;
}
static void kem_free(kem_t *k) { OQS_KEM_free(k->q); k->q = NULL; }
static const char *kem_lib(const kem_t *k) {  /* no spaces: it goes into the #kem line */
    static char s[64];
    snprintf(s, sizeof s, "%s%s%s%s%s", k->q ? "liboqs_" : "", k->q ? OQS_version() : "", k->q && k->x ? "+" : "",
             k->x ? "OpenSSL_" : "", k->x ? OpenSSL_version(OPENSSL_VERSION_STRING) : "");
    return s;
}
static int x25519_keypair(unsigned char pub[32], unsigned char priv[32]) {
    EVP_PKEY *p = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    size_t a = 32, b = 32;
    int ok = p && EVP_PKEY_get_raw_public_key(p, pub, &a) == 1 && EVP_PKEY_get_raw_private_key(p, priv, &b) == 1;
    EVP_PKEY_free(p);
    return ok;
}
static int x25519_dh(unsigned char out[32], const unsigned char priv[32], const unsigned char peer[32]) {
    EVP_PKEY *a = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32),
             *b = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    EVP_PKEY_CTX *c = a ? EVP_PKEY_CTX_new(a, NULL) : NULL;
    size_t n = 32;
    int ok = c && b && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, b) == 1 &&
             EVP_PKEY_derive(c, out, &n) == 1;
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(a); EVP_PKEY_free(b);
    return ok;
}
static int kem_keypair(const kem_t *k, unsigned char *pk, unsigned char *sk) {
    if (k->q && OQS_KEM_keypair(k->q, pk, sk) != OQS_SUCCESS) return 0;
    return !k->x || x25519_keypair(pk + k->pk - 32, sk + k->sk - 32);
}
static int kem_encaps(const kem_t *k, unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    unsigned char e[32];
    if (k->q && OQS_KEM_encaps(k->q, ct, ss, pk) != OQS_SUCCESS) return 0;
    int ok = !k->x || (x25519_keypair(ct + k->ct - 32, e) && x25519_dh(ss + k->ss - 32, e, pk + k->pk - 32));
    OPENSSL_cleanse(e, sizeof e);
    return ok;
}
static int kem_decaps(const kem_t *k, unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    if (k->q && OQS_KEM_decaps(k->q, ss, ct, sk) != OQS_SUCCESS) return 0;
    return !k->x || x25519_dh(ss + k->ss - 32, sk + k->sk - 32, ct + k->ct - 32);
}

/* the device side of the KEM exchange: see the header comment */
static void kem_exchange(conn_t *c, int iter, int n, int warm, const char *name, int report) {
    kem_t k;
    if (!kem_new(&k, name)) die("unknown or disabled KEM", name);
    char pk_topic[160], ct_topic[64];
    snprintf(pk_topic, sizeof pk_topic, "pqc/kem/%d/pk/%s", (int)getpid(), name);
    snprintf(ct_topic, sizeof ct_topic, "pqc/kem/%d/ct", (int)getpid());
    size_t cap = k.pk + k.ct + 512;
    unsigned char *pk = malloc(k.pk), *sk = malloc(k.sk), *ss = malloc(k.ss), *pkt = malloc(cap), *body = malloc(cap),
                  h[32], type;
    if (!pk || !sk || !ss || !pkt || !body) die("out of memory", name);
    subscribe(c, ct_topic);
    for (int x = 0; x < warm + n; x++) {
        double t0 = now_us();
        if (!kem_keypair(&k, pk, sk)) die("key pair failed", name);
        double ta = now_us();
        int pl = publish_packet(pkt, pk_topic, pk, k.pk), len;
        uint64_t tx0 = c->tx, rx0 = c->rx;
        double t1 = now_us();
        if (io_write(c, pkt, pl) != pl) die("mqtt publish failed", "write");
        do len = read_packet(c, &type, body, (int)cap);  /* skip anything that isn't the reply */
        while (len >= 0 && (type & 0xF0) != 0x30);
        double t2 = now_us();
        if (len < 0) die("kem exchange failed", "no reply (is the responder running next to the broker?)");
        int off = 2 + (body[0] << 8 | body[1]);
        const unsigned char *r = body + off;
        if ((size_t)(len - off) != k.ct + 36) die("kem exchange failed", "reply has the wrong length");
        if (!kem_decaps(&k, ss, r, sk)) die("decapsulation failed", name);
        double t3 = now_us();
        sha256(ss, k.ss, h);
        if (memcmp(h, r + k.ct, 32)) die("kem exchange failed", "the shared secrets differ");
        const unsigned char *e = r + k.ct + 32;
        unsigned enc_us = e[0] | e[1] << 8 | e[2] << 16 | (unsigned)e[3] << 24;
        if (report && x >= warm)
            printf("kex,%d,%d,%.3f,%.3f,%.3f,%u,%llu,%llu\n", iter, x - warm, ta - t0, t2 - t1, t3 - t2, enc_us,
                   (unsigned long long)(c->tx - tx0), (unsigned long long)(c->rx - rx0));
    }
    OQS_MEM_secure_free(sk, k.sk); OQS_MEM_secure_free(ss, k.ss);
    free(pk); free(pkt); free(body); kem_free(&k);
}

/* the responder next to the broker: encapsulates every public key on pqc/kem/+/pk/+, replies on pqc/kem/<id>/ct */
static void kem_respond(conn_t *c) {
    size_t cap = 2u << 20;  /* the largest public key, Classic-McEliece-8192128's 1,357,824 B, fits */
    unsigned char *body = malloc(cap), *pkt = malloc(cap), *reply = malloc(cap), type;
    kem_t k = {0};
    char cur[64] = "";
    int len, ok = 0;
    if (!body || !pkt || !reply) die("out of memory", "kem responder");
    subscribe(c, "pqc/kem/+/pk/+");
    printf("[kem responder] liboqs %s: encapsulates public keys on pqc/kem/+/pk/+\n", OQS_version());
    fflush(stdout);
    while ((len = read_packet(c, &type, body, (int)cap)) >= 0) {
        if ((type & 0xF0) != 0x30 || len < 2) continue;
        int tl = body[0] << 8 | body[1];
        char topic[256], id[32], name[64], out_topic[64];
        snprintf(topic, sizeof topic, "%.*s", tl, (const char *)body + 2);
        if (sscanf(topic, "pqc/kem/%31[^/]/pk/%63s", id, name) != 2) continue;
        if (strcmp(name, cur)) { kem_free(&k); ok = kem_new(&k, name); snprintf(cur, sizeof cur, "%s", name); }
        if (!ok || (size_t)(len - 2 - tl) != k.pk) {
            fprintf(stderr, "[kem responder] %s: unknown KEM or wrong key length\n", name);
            continue;
        }
        unsigned char ss[128];
        double t0 = now_us();
        int st = kem_encaps(&k, reply, ss, body + 2 + tl);
        unsigned us = (unsigned)(now_us() - t0 + 0.5);
        if (!st) { fprintf(stderr, "[kem responder] %s: encapsulation failed\n", name); continue; }
        sha256(ss, k.ss, reply + k.ct);
        unsigned char *e = reply + k.ct + 32;
        e[0] = us; e[1] = us >> 8; e[2] = us >> 16; e[3] = us >> 24;
        snprintf(out_topic, sizeof out_topic, "pqc/kem/%s/ct", id);
        int pl = publish_packet(pkt, out_topic, reply, k.ct + 36);
        if (io_write(c, pkt, pl) != pl) die("kem responder", "publish failed");
        printf("[kem responder] %s from %s: %zu B key -> %zu B ciphertext, encapsulation %u us\n", name, id, k.pk, k.ct, us);
        fflush(stdout);
    }
    kem_free(&k);
}
#endif

/* watch mode: print each PUBLISH the broker delivers to this independent subscriber */
static void watch(conn_t *c, const char *filter, const char *name) {
    static unsigned char body[2048], pt[1024];
    unsigned char type;
    int len;
    subscribe(c, filter);
    printf("[watch %s] subscribed to %s%s\n", name, filter,
           have_keys ? " (holds the pipeline's keys: decrypts)" : " (no keys: shows ciphertext)");
    fflush(stdout);
    while ((len = read_packet(c, &type, body, sizeof body)) >= 0) {
        if ((type & 0xF0) != 0x30 || len < 2) continue;              /* PUBLISH only */
        int tl = body[0] << 8 | body[1], fl = len - 2 - tl, n = -1;
        const unsigned char *f = body + 2 + tl;
        char topic[256];
        snprintf(topic, sizeof topic, "%.*s", tl, (const char *)body + 2);
        struct timeval tv; struct tm tm;
        gettimeofday(&tv, NULL); localtime_r(&tv.tv_sec, &tm);
        printf("[watch %s] %02d:%02d:%02d.%06ld  %s  %d B", name, tm.tm_hour, tm.tm_min, tm.tm_sec,
               (long)tv.tv_usec, topic, fl);
        if (fl >= APP_HDR) printf("  FCnt %d", f[6] | f[7] << 8);
        for (int k = 0; have_keys && n < 0 && APP_AEAD_NAMES[k]; k++)  /* the scheme that verifies */
            if (app_aead_init(APP_AEAD_NAMES[k]) == 0) { use_shared_keys(); n = app_open(f, fl, pt); }
        int printable = fl > APP_HDR;
        for (int i = APP_HDR; i < fl; i++) printable &= isprint(f[i]) != 0;
        if (n >= 0) {
            while (n > 0 && pt[n - 1] == ' ') n--;
            printf("  -> %.*s  (%s: verified)\n", n, (const char *)pt, app_aead_label());
        } else if (printable) {
            n = fl - APP_HDR;
            while (n > 0 && f[APP_HDR + n - 1] == ' ') n--;
            printf("  -> %.*s  (none: no MIC / tag, unprotected)\n", n, (const char *)f + APP_HDR);
        } else {
            printf("  -> %s ", have_keys ? "REJECTED (no scheme verifies):" : "ciphertext");
            for (int i = APP_HDR; i < fl && i < APP_HDR + 16; i++) printf("%02x", f[i]);
            printf("...\n");
        }
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6 && argc != 8) {
        fprintf(stderr, "usage: %s host port iters warmup [CAfile [cert key]]\n", argv[0]);
        return 2;
    }
    const char *host = argv[1], *port = argv[2], *ca = argc > 5 ? argv[5] : NULL;
    const char *cert = argc > 7 ? argv[6] : NULL, *key = argc > 7 ? argv[7] : NULL;
    const char *group = getenv("GROUP") ? getenv("GROUP") : "X25519MLKEM768";
    const char *aead = getenv("AEAD") ? getenv("AEAD") : "none";
    int iters = atoi(argv[3]), warm = atoi(argv[4]);
    int down = getenv("DOWN") && atoi(getenv("DOWN"));
    int msgs = getenv("MSGS") ? atoi(getenv("MSGS")) : 0, payload = getenv("PAYLOAD") ? atoi(getenv("PAYLOAD")) : 51;
    char topic[64];
    snprintf(topic, sizeof topic, "pqc/pipe/%d", (int)getpid());
    const char *hex = getenv("APP_KEYS"), *sub = getenv("SUB");
    if (hex) {
        for (int i = 0; i < 64; i++) {
            unsigned v;
            if (!isxdigit((unsigned char)hex[2 * i]) || sscanf(hex + 2 * i, "%2x", &v) != 1) die("APP_KEYS", "needs 128 hex chars");
            keys[i] = (unsigned char)v;
        }
        have_keys = 1;
    }
    if (msgs > 0) {
        if (payload < 1 || payload > 1024) die("PAYLOAD must be 1..1024 bytes", "");
        if (app_aead_init(aead)) die("unknown or unavailable AEAD", aead);
        if (app_aead_selftest()) die("app_aead self-check failed", aead);
        use_shared_keys();  /* the self-test re-keys randomly, so after it */
    }

    struct addrinfo hints = {0}, *ai;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0) die("cannot resolve", host);
    if (ca) tls_init(ca, cert, key, group, getenv("SUITE"));
    const char *kem = getenv("KEM");
#ifdef HAVE_LIBOQS
    int kexs = getenv("KEXS") ? atoi(getenv("KEXS")) : 50, kex_warm = getenv("KEX_WARM") ? atoi(getenv("KEX_WARM")) : 2;
#else
    if (kem || getenv("KEM_RESPOND")) die("KEM exchange", "this build has no liboqs: use mqtt_kem_timer (build_timer.sh)");
#endif
    if (sub || getenv("KEM_RESPOND")) {  /* watch / responder: one connection, then serve until killed */
        conn_t c = {0};
        unsigned char pkt[64], ack[4];
        char id[32];
        int r, n;
        c.fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (connect(c.fd, ai->ai_addr, ai->ai_addrlen) != 0) die("tcp connect failed (no listener?)", strerror(errno));
        if (ca && (r = tls_connect(&c)) != 0) die("tls handshake failed", tls_err(&c, r));
        snprintf(id, sizeof id, "pqc-%s-%d", sub ? "watch" : "kem", (int)getpid());  /* own id: a shared one would evict the timer */
        n = connect_packet(pkt, id, 0);
        if (io_write(&c, pkt, n) != n || io_read_n(&c, ack, 4) != 4 || ack[0] != 0x20 || ack[3] != 0)
            die("mqtt connect failed", sub ? "watch mode" : "kem responder");
#ifdef HAVE_LIBOQS
        if (!sub) { kem_respond(&c); return 0; }
#endif
        watch(&c, sub, getenv("WATCH_NAME") ? getenv("WATCH_NAME") : host);
        return 0;
    }
    printf("#lib %s\n", ca ? tls_version() : "none (plain MQTT)");
    if (msgs > 0) printf("#aead %s (%s), %s, %d B payload + %d B overhead\n", app_aead_label(), app_aead_library(),
                         down ? "downlink" : "uplink",
                         payload, app_aead_overhead());
#ifdef HS_TIMING
    printf("iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,tx_segs,"
           "rx_segs," HS_COLS "\n");
#else
    printf("iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,tx_segs,rx_segs\n");
#endif
    if (msgs > 0) printf("msg,iter,idx,seal_us,rtt_us,open_us,tx_B,rx_B\n");
#ifdef HAVE_LIBOQS
    if (kem) {
        kem_t k;
        if (!kem_new(&k, kem)) die("unknown or disabled KEM", kem);
        printf("#kem %s lib=%s pk_B=%zu ct_B=%zu ss_B=%zu nist_level=%d\n", kem, kem_lib(&k), k.pk, k.ct, k.ss, k.level);
        kem_free(&k);
        printf("kex,iter,idx,keygen_us,rtt_us,decaps_us,encaps_us,tx_B,rx_B\n");
    }
#endif

    unsigned char connect_pkt[64];  /* MQTT 3.1.1, clean session, keepalive 60 s, client id "pqc-timer" */
    int connect_len = connect_packet(connect_pkt, "pqc-timer", 60);
    static const unsigned char disconnect_pkt[] = {0xE0, 0};
    struct timeval tmo = {10, 0};

    for (int i = 0; i < warm + iters; i++) {
        conn_t c = {0};
        double t0 = now_ms();
        c.fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        setsockopt(c.fd, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof tmo);  /* a silent broker fails, not hangs */
        int one = 1;  /* no Nagle delay on small PUBLISHes: latency is what is being measured */
        setsockopt(c.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(c.fd, ai->ai_addr, ai->ai_addrlen) != 0) die("tcp connect failed (no listener?)", strerror(errno));
        double t1 = now_ms();
        int r;
#ifdef HS_TIMING
        hs_reset();
#endif
        if (ca && (r = tls_connect(&c)) != 0) die("tls handshake failed", tls_err(&c, r));
        double t2 = now_ms();
#ifdef HS_TIMING
        hs_times_t hs = hs_t;
#endif
        uint64_t hs_tx = c.tx, hs_rx = c.rx, hs_w = c.io[0], hs_r = c.io[1];
        unsigned char ack[4];
        if ((io_write(&c, connect_pkt, connect_len) != connect_len ||
                          (r = io_read_n(&c, ack, 4)) != 4))
            die("mqtt connect failed", ca ? tls_err(&c, r) : "connection closed by broker");
        if (ack[0] != 0x20 || ack[3] != 0) {
            char rc[32]; snprintf(rc, sizeof rc, "CONNACK return code %d", ack[3]);
            die("mqtt connect refused", rc);
        }
        double t3 = now_ms();
        uint64_t segs_tx, segs_rx;   /* the whole connect: TCP + TLS + CONNECT / CONNACK */
        tcp_segments(c.fd, &segs_tx, &segs_rx);
        if (i == warm && c.tls) printf("#suite %s\n", tls_cipher(&c));
        if (i >= warm)
            printf("%d,%.4f,%.4f,%.4f,%.4f,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu", i - warm,
                   t1 - t0, t2 - t1, t3 - t2, t3 - t0, (unsigned long long)hs_tx, (unsigned long long)hs_rx,
                   (unsigned long long)(c.tx - hs_tx), (unsigned long long)(c.rx - hs_rx),
                   (unsigned long long)hs_w, (unsigned long long)hs_r, (unsigned long long)c.io[0],
                   (unsigned long long)c.io[1], (unsigned long long)segs_tx, (unsigned long long)segs_rx);
#ifdef HS_TIMING
        if (i >= warm) printf(HS_FMT, HS_ARGS(hs));
#endif
        if (i >= warm) printf("\n");
        if (msgs > 0) pipeline(&c, i - warm, msgs, payload, topic, i >= warm, down);
#ifdef HAVE_LIBOQS
        if (kem) kem_exchange(&c, i - warm, kexs, kex_warm, kem, i >= warm);
#endif
        io_write(&c, disconnect_pkt, sizeof disconnect_pkt);
        if (c.tls) tls_close(&c);
        close(c.fd);
    }
    freeaddrinfo(ai);
    return 0;
}
