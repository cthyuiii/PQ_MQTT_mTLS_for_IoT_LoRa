/* wire_stats.h - how one TLS / MQTT connection used the network, for mqtt_tls_timer.c:
 *   - socket writes / reads that moved data (each is one send() / recv(), i.e. one or more TLS records);
 *   - the TCP segments the kernel sent / received on the socket, SYN and pure ACKs included.
 * Approximate on-wire bytes = TLS / TCP payload + WIRE_HDR_B per segment (IPv4 20 + TCP 20 + timestamp option
 * 12). Link-layer headers (Ethernet 18, Wi-Fi ~30) are not included; over IPv6 add 20 per segment. The segment
 * count depends on the path (MTU, delayed ACKs), which is why it only means something between two machines. */
#pragma once
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define WIRE_HDR_B 52

/* segments sent / received on this socket so far (0 / 0 where the OS doesn't report them) */
static void tcp_segments(int fd, uint64_t *tx, uint64_t *rx) {
    *tx = *rx = 0;
#if defined(__APPLE__)
    struct tcp_connection_info ti;
    socklen_t l = sizeof ti;
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &ti, &l) == 0) { *tx = ti.tcpi_txpackets; *rx = ti.tcpi_rxpackets; }
#elif defined(__linux__)
    /* the kernel's struct tcp_info up to tcpi_segs_out / tcpi_segs_in (Linux 4.2+; the kernel only appends
     * fields). glibc's copy of the struct stops before them. */
    struct { uint8_t u8[8]; uint32_t u32[24]; uint64_t u64[4]; uint32_t segs_out, segs_in; } ti;
    socklen_t l = sizeof ti;
    memset(&ti, 0, sizeof ti);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &l) == 0 && l >= sizeof ti) { *tx = ti.segs_out; *rx = ti.segs_in; }
#endif
}

#ifndef USE_WOLFSSL
#include <openssl/bio.h>
/* socket-BIO callback: n[0] += 1 per write, n[1] += 1 per read that moved data */
static long count_io(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int ret, size_t *processed) {
    (void)argp; (void)len; (void)argi; (void)argl;
    uint64_t *n = (uint64_t *)BIO_get_callback_arg(b);
    if (n && ret > 0 && processed && *processed > 0) {
        if (oper == (BIO_CB_WRITE | BIO_CB_RETURN)) n[0]++;
        else if (oper == (BIO_CB_READ | BIO_CB_RETURN)) n[1]++;
    }
    return ret;
}
static void count_socket_io(BIO *b, uint64_t n[2]) {
    BIO_set_callback_arg(b, (char *)n);
    BIO_set_callback_ex(b, count_io);
}
#endif
