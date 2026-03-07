#!/bin/bash
# run-fixpoint.sh - Fixpoint of Theseus: fixed-point proof
#
# Proves the MVM compiler + x64 translator is a fixed point:
#   SBCL → Gen0 → Gen1 → Gen2, SHA256(Gen1) == SHA256(Gen2)
#
# Usage: cd lib/modus64 && ./scripts/run-fixpoint.sh

set -e
cd "$(dirname "$0")/.."

TIMEOUT=${FIXPOINT_TIMEOUT:-30}
GEN0=/tmp/fixpoint-gen0.elf
GEN1=/tmp/fixpoint-gen1.bin
GEN2=/tmp/fixpoint-gen2.bin

cleanup() {
  pkill -f "qemu-system-x86_64.*fixpoint" 2>/dev/null || true
  rm -f /tmp/qmp-fixpoint.sock
}
trap cleanup EXIT

extract_image() {
  local kernel=$1 output=$2 label=$3
  local sock=/tmp/qmp-fixpoint.sock

  rm -f "$sock" "$output"
  qemu-system-x86_64 -kernel "$kernel" -m 512 -nographic -no-reboot \
    -qmp "unix:$sock,server=on,wait=off" &
  local pid=$!

  # Wait for build to complete
  sleep "$TIMEOUT"

  python3 -c "
import socket, json, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$sock')
def recv():
    d = b''
    while True:
        d += s.recv(4096)
        try: return json.loads(d)
        except: continue
recv()
s.sendall(json.dumps({'execute': 'qmp_capabilities'}).encode() + b'\n')
recv()
s.sendall(json.dumps({'execute': 'pmemsave', 'arguments': {
    'val': 0x08000000, 'size': 2097216, 'filename': '$output'
}}).encode() + b'\n')
recv()
time.sleep(1)
s.sendall(json.dumps({'execute': 'quit'}).encode() + b'\n')
s.close()
" 2>/dev/null

  sleep 1
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true

  if [ ! -f "$output" ]; then
    echo "FAIL: $label - output file not created"
    exit 1
  fi
  echo "$label: $(sha256sum "$output" | cut -d' ' -f1)"
}

echo "=== Fixpoint of Theseus ==="
echo ""

# Step 0: Build Gen0 from SBCL
echo "Step 0: SBCL → Gen0"
sbcl --script mvm/build-fixpoint.lisp 2>&1 | grep -E "bytecode:|Functions:|native code:|written"
echo ""

# Step 1: Gen0 → Gen1
echo "Step 1: Gen0 → Gen1"
extract_image "$GEN0" "$GEN1" "Gen1"
echo ""

# Step 2: Gen1 → Gen2
echo "Step 2: Gen1 → Gen2"
extract_image "$GEN1" "$GEN2" "Gen2"
echo ""

# Compare
echo "=== Result ==="
hash1=$(sha256sum "$GEN1" | cut -d' ' -f1)
hash2=$(sha256sum "$GEN2" | cut -d' ' -f1)

if [ "$hash1" = "$hash2" ]; then
  echo "PASS: SHA256(Gen1) == SHA256(Gen2)"
  echo "  $hash1"
else
  echo "FAIL: SHA256(Gen1) != SHA256(Gen2)"
  echo "  Gen1: $hash1"
  echo "  Gen2: $hash2"
  exit 1
fi
