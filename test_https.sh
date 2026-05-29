#!/usr/bin/env bash
# Smoke-test https_shell.py: starts the server, fires a beacon, checks 404.
# Run from the repo root:  bash test_https.sh

set -euo pipefail

PORT=8443

echo "[*] Starting https_shell.py server on port $PORT..."
tail -f /dev/null | python3 https_shell.py server --port "$PORT" &
SERVER_PID=$!
sleep 3

cleanup() { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

python3 - <<'EOF'
import ssl, sys, urllib.request, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE
base = "https://127.0.0.1:8443"

# Empty beacon (no command queued)
req = urllib.request.Request(f"{base}/b", headers={"User-Agent": "test"})
with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
    data = json.loads(r.read())
assert data == {"id": 0, "cmd": ""}, f"unexpected beacon: {data}"
print(f"[+] GET /b  → {data}")

# Unknown path returns 404
try:
    urllib.request.urlopen(
        urllib.request.Request(f"{base}/notfound"), context=ctx, timeout=5
    )
    sys.exit("[!] expected 404, got 200")
except urllib.error.HTTPError as e:
    assert e.code == 404, f"expected 404, got {e.code}"
    print(f"[+] GET /notfound → {e.code}")

print("[*] All checks passed.")
EOF
