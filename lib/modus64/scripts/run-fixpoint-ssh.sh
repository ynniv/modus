#!/bin/bash
# run-fixpoint-ssh.sh - Multi-architecture fixpoint chain with SSH final stage
#
# Chains multiple fixpoint generations across architectures, then boots the
# final generation as an SSH server.
#
# Usage: cd lib/modus64 && ./scripts/run-fixpoint-ssh.sh x64 aarch64 [x64 aarch64 ...]
#   First arch must be x64 (SBCL builds Gen0 for x64).
#   Last arch boots as SSH server.
#   Minimum 2 architectures.
#
# Example:
#   ./scripts/run-fixpoint-ssh.sh x64 aarch64
#     Gen0 (x64) cross-compiles → Gen1 (AArch64, SSH)
#
#   ./scripts/run-fixpoint-ssh.sh x64 aarch64 x64 aarch64
#     Gen0 (x64) → Gen1 (AArch64) → Gen2 (x64) → Gen3 (AArch64, SSH)

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$0")/.."

TIMEOUT=${FIXPOINT_TIMEOUT:-90}
ARCHS=("$@")

# Validate arguments
if [[ ${#ARCHS[@]} -lt 2 ]]; then
  echo "Usage: $0 arch1 arch2 [arch3 ...]"
  echo "  Architectures: x64, aarch64"
  echo "  First must be x64. Last boots as SSH server."
  exit 1
fi

if [[ "${ARCHS[0]}" != "x64" ]]; then
  echo "Error: first architecture must be x64 (SBCL builds Gen0 for x64)"
  exit 1
fi

for arch in "${ARCHS[@]}"; do
  if [[ "$arch" != "x64" && "$arch" != "aarch64" ]]; then
    echo "Error: unknown architecture '$arch' (valid: x64, aarch64)"
    exit 1
  fi
done

# Architecture helpers
arch_id() {
  if [[ "$1" == "x64" ]]; then echo 0; else echo 1; fi
}

NO_THP="$(cd "$SCRIPT_DIR/../../.." && pwd)/modus/scripts/no-thp-exec"

run_qemu() {
  # Runs QEMU directly with no-thp-exec wrapper to avoid THP compaction stalls
  local arch=$1 kernel=$2; shift 2
  if [[ "$arch" == "x64" ]]; then
    "$NO_THP" qemu-system-x86_64 -kernel "$kernel" -m 512 -nographic -no-reboot "$@"
  else
    "$NO_THP" qemu-system-aarch64 -M virt -cpu cortex-a53 -m 512 -kernel "$kernel" -nographic "$@"
  fi
}

extract_pa() {
  # Physical address where generated image is written in QEMU memory
  if [[ "$1" == "x64" ]]; then
    echo 134217728    # 0x08000000
  else
    echo 1207959552   # 0x48000000 (VA 0x08000000 + 0x40000000 MMU offset)
  fi
}

metadata_file_offset() {
  # File offset of MVMT metadata within the image
  if [[ "$1" == "x64" ]]; then
    echo 2097152      # 0x200000
  else
    echo 2621440      # 0x280000
  fi
}

image_extract_size() {
  # Total image size to extract via pmemsave
  if [[ "$1" == "x64" ]]; then
    echo 2097216      # 0x200000 + 64 (metadata)
  else
    echo 2621504      # 0x280000 + 64 (metadata)
  fi
}

patch_u32_le() {
  # Write a u32 LE value at a file offset
  local file=$1 offset=$2 value=$3
  local b0=$((value & 0xFF))
  local b1=$(( (value >> 8) & 0xFF ))
  local b2=$(( (value >> 16) & 0xFF ))
  local b3=$(( (value >> 24) & 0xFF ))
  printf "\\x$(printf '%02x' $b0)\\x$(printf '%02x' $b1)\\x$(printf '%02x' $b2)\\x$(printf '%02x' $b3)" | \
    dd of="$file" bs=1 seek="$offset" conv=notrunc 2>/dev/null
}

cleanup() {
  pkill -f "qemu-system.*fixpoint-gen" 2>/dev/null || true
  rm -f /tmp/qmp-fixpoint-ssh.sock /tmp/fixpoint-ssh-serial.txt
}
trap cleanup EXIT

# ============================================================
# Step 0: Build Gen0 from SBCL (with --ssh networking source)
# ============================================================

N=${#ARCHS[@]}
LAST=$((N - 1))

echo "=== Fixpoint SSH Chain: ${ARCHS[*]} ==="
echo "  Generations: $N (Gen0..Gen$LAST)"
echo "  SSH on: Gen$LAST (${ARCHS[$LAST]})"
echo ""
echo "Step 0: SBCL → Gen0 (x64, --ssh)"
sbcl --script mvm/build-fixpoint.lisp -- --ssh 2>&1 | grep -E "bytecode:|Functions:|native code:|written|SSH mode|Networking"
echo ""

GEN=/tmp/fixpoint-gen0.elf

# ============================================================
# Chain: Gen0..Gen(N-2) cross-compile
# ============================================================

for ((i = 0; i < LAST; i++)); do
  NEXT=$((i + 1))
  ARCH="${ARCHS[$i]}"
  TARGET="${ARCHS[$NEXT]}"
  NEXT_IMG="/tmp/fixpoint-gen${NEXT}.bin"
  SOCK="/tmp/qmp-fixpoint-ssh.sock"
  SERIAL="/tmp/fixpoint-ssh-serial.txt"

  echo "Step $((i + 1)): Gen$i ($ARCH) → Gen$NEXT ($TARGET)"

  # Patch target-architecture in current image metadata
  MD_OFF=$(metadata_file_offset "$ARCH")
  TARGET_ID=$(arch_id "$TARGET")
  patch_u32_le "$GEN" $((MD_OFF + 52)) "$TARGET_ID"

  # Ensure mode=0 (cross-compile) for this generation
  patch_u32_le "$GEN" $((MD_OFF + 56)) 0

  rm -f "$SOCK" "$NEXT_IMG" "$SERIAL"

  # Boot with QMP socket and serial to file
  run_qemu "$ARCH" "$GEN" -qmp "unix:$SOCK,server=on,wait=off" -display none -serial "file:$SERIAL" &
  PID=$!

  # Wait for DONE marker on serial output
  ELAPSED=0
  while ! grep -q "DONE" "$SERIAL" 2>/dev/null; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
      echo "  TIMEOUT after ${TIMEOUT}s"
      kill "$PID" 2>/dev/null || true
      wait "$PID" 2>/dev/null || true
      echo "  Serial output:"
      cat "$SERIAL" 2>/dev/null || true
      exit 1
    fi
  done
  echo "  Completed in ${ELAPSED}s"

  # Extract next-gen image via QMP pmemsave
  ADDR=$(extract_pa "$ARCH")
  SIZE=$(image_extract_size "$TARGET")
  python3 -c "
import socket, json, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$SOCK')
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
    'val': $ADDR, 'size': $SIZE, 'filename': '$NEXT_IMG'
}}).encode() + b'\n')
recv()
time.sleep(1)
s.sendall(json.dumps({'execute': 'quit'}).encode() + b'\n')
s.close()
" 2>/dev/null

  # Wait for QEMU to exit
  sleep 1
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  rm -f "$SERIAL"

  if [[ ! -f "$NEXT_IMG" ]]; then
    echo "  FAIL: Gen$NEXT not extracted"
    exit 1
  fi
  echo "  Gen$NEXT extracted: $(wc -c < "$NEXT_IMG") bytes ($TARGET)"
  echo ""

  GEN="$NEXT_IMG"
done

# ============================================================
# Boot final generation as SSH server
# ============================================================

FINAL_ARCH="${ARCHS[$LAST]}"
echo "=== Booting Gen$LAST ($FINAL_ARCH) as SSH server ==="

# Patch mode=1 (SSH server)
MD_OFF=$(metadata_file_offset "$FINAL_ARCH")
patch_u32_le "$GEN" $((MD_OFF + 56)) 1

# Launch QEMU with E1000 networking and SSH port forwarding
echo ""
echo "SSH available at: ssh -p 2222 test@localhost"
echo "Press Ctrl-C to stop."
echo ""
run_qemu "$FINAL_ARCH" "$GEN" -device 'e1000,netdev=net0,romfile=,rombar=0' -netdev 'user,id=net0,hostfwd=tcp::2222-:22'
