#!/bin/bash
# test-fixpoint-ssh.sh - Comprehensive fixpoint SSH test matrix
#
# Tests all (host, target) architecture pairs for SSH connectivity.
# Chain: SBCL → Gen0 (x64) → Gen1 (host) → Gen2 (target, SSH)
# When host=x64: SBCL → Gen0 (x64) → Gen1 (target, SSH)
#
# Usage:
#   ./scripts/test-fixpoint-ssh.sh                    # all 16 combos
#   ./scripts/test-fixpoint-ssh.sh x64 aarch64         # single combo
#   ./scripts/test-fixpoint-ssh.sh x64                 # all targets for host=x64
#   ./scripts/test-fixpoint-ssh.sh --quick             # x64 targets only (4 tests)
#   ./scripts/test-fixpoint-ssh.sh --resume arm32 i386 # skip earlier combos

set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

SSH_PORT=2223
ALL_ARCHS=(x64 aarch64 i386 arm32)

PASS=0
FAIL=0
SKIP=0
TOTAL=0
declare -A RESULTS

# Parse arguments
HOSTS=()
TARGETS=()
RESUME_FROM=""

if [[ $# -eq 0 ]]; then
  HOSTS=("${ALL_ARCHS[@]}")
  TARGETS=("${ALL_ARCHS[@]}")
elif [[ "$1" == "--quick" ]]; then
  HOSTS=(x64)
  TARGETS=("${ALL_ARCHS[@]}")
elif [[ "$1" == "--resume" ]]; then
  HOSTS=("${ALL_ARCHS[@]}")
  TARGETS=("${ALL_ARCHS[@]}")
  RESUME_FROM="${2}_${3}"
elif [[ $# -eq 1 ]]; then
  HOSTS=("$1")
  TARGETS=("${ALL_ARCHS[@]}")
elif [[ $# -eq 2 ]]; then
  HOSTS=("$1")
  TARGETS=("$2")
else
  echo "Usage: $0 [host [target]]"
  echo "       $0 --quick          # x64 host only"
  echo "       $0 --resume host target"
  exit 1
fi

# Timeouts per architecture pair (seconds)
# Cross-compilation: depends on BOTH host (emulation speed) and target (translator complexity)
# AArch64 translator is ~4x slower than x64/arm32/i386 translators
cross_timeout() {
  local host=$1 target=$2
  # Base time by target translator complexity
  local base
  case "$target" in
    x64)     base=60 ;;
    aarch64) base=300 ;;   # AArch64 translator is heaviest (~240s on x64)
    i386)    base=60 ;;
    arm32)   base=60 ;;
  esac
  # Scale by host emulation speed
  case "$host" in
    x64)     echo $base ;;
    aarch64) echo $((base * 2)) ;;
    i386)    echo $((base * 3)) ;;
    arm32)   echo $((base * 2)) ;;
  esac
}

# SSH boot timeout depends on the target architecture
# Includes Ed25519/X25519 precomputation at boot (slow on emulated archs)
# i386 uses 30-bit pair arithmetic for crypto — much slower
boot_timeout() {
  case "$1" in
    x64)     echo 120 ;;
    aarch64) echo 180 ;;
    i386)    echo 300 ;;
    arm32)   echo 360 ;;
  esac
}

cleanup_qemu() {
  pkill -f "qemu-system.*fixpoint-gen" 2>/dev/null || true
  pkill -f "qemu-system.*2223" 2>/dev/null || true
  sleep 1
  # Ensure port is free
  if ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT} "; then
    sleep 2
  fi
}

test_ssh_combo() {
  local host=$1 target=$2
  local label="${host} → ${target}"
  local key="${host}_${target}"

  # Build chain args
  local chain
  if [[ "$host" == "x64" ]]; then
    chain="x64 ${target}"
  else
    chain="x64 ${host} ${target}"
  fi

  # Calculate total timeout: x64→host cross-compile + host→target cross-compile + SSH boot
  local xtimeout
  if [[ "$host" == "x64" ]]; then
    xtimeout=$(( $(cross_timeout x64 "$target") + $(boot_timeout "$target") ))
  else
    # x64→host + host→target + boot
    xtimeout=$(( $(cross_timeout x64 "$host") + $(cross_timeout "$host" "$target") + $(boot_timeout "$target") ))
  fi
  # Add buffer for SBCL build (Gen0) overhead per run
  xtimeout=$((xtimeout + 90))

  local log="/tmp/fixpoint-test-${host}-${target}.log"
  rm -f "$log"

  printf "  %-18s " "($label)"

  # Run fixpoint SSH chain in background
  FIXPOINT_TIMEOUT=$xtimeout timeout $((xtimeout + 60)) \
    ./scripts/run-fixpoint-ssh.sh $chain > "$log" 2>&1 &
  local pid=$!

  # Wait for SSH to be ready by trying actual SSH connections
  # The kernel prints "SSH" when ready on some archs, but not all.
  # Most reliable: just try connecting periodically.
  local elapsed=0
  local ssh_ready=0
  # Give it time to boot before first attempt
  sleep 30
  elapsed=30
  while [[ $elapsed -lt $xtimeout ]]; do
    # Check if process died
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    # Try SSH connection (quick timeout)
    local probe
    probe=$(echo '(+ 1 2)' | timeout 15 \
      ssh -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          -p $SSH_PORT test@localhost 2>&1)
    if echo "$probe" | grep -q "= 3"; then
      ssh_ready=1
      break
    fi
    sleep 15
    elapsed=$((elapsed + 15))
  done

  local result="FAIL"
  if [[ $ssh_ready -eq 1 ]]; then
    result="PASS"
  else
    # Check if cross-compilation failed vs SSH boot failed
    if grep -q "TIMEOUT" "$log" 2>/dev/null; then
      result="FAIL(timeout)"
    elif grep -q "FAIL" "$log" 2>/dev/null; then
      result="FAIL(build)"
    else
      result="FAIL(boot)"
    fi
  fi

  # Cleanup
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  cleanup_qemu

  # Record result
  RESULTS[$key]="$result"
  if [[ "$result" == "PASS" ]]; then
    printf "PASS  (%ds)\n" "$elapsed"
    PASS=$((PASS + 1))
  else
    printf "%s  (log: %s)\n" "$result" "$log"
    FAIL=$((FAIL + 1))
  fi
  TOTAL=$((TOTAL + 1))
}

# ============================================================
# Main
# ============================================================

echo "=== Fixpoint SSH Test Matrix ==="
echo "  Hosts:   ${HOSTS[*]}"
echo "  Targets: ${TARGETS[*]}"
echo "  Tests:   $((${#HOSTS[@]} * ${#TARGETS[@]}))"
echo ""

# Ensure no stale QEMU
cleanup_qemu

# Run tests
SKIPPING=1
if [[ -z "$RESUME_FROM" ]]; then
  SKIPPING=0
fi

for host in "${HOSTS[@]}"; do
  echo "Host: ${host}"
  for target in "${TARGETS[@]}"; do
    key="${host}_${target}"
    if [[ $SKIPPING -eq 1 ]]; then
      if [[ "$key" == "$RESUME_FROM" ]]; then
        SKIPPING=0
      else
        printf "  %-18s SKIP (resume)\n" "(${host} → ${target})"
        RESULTS[$key]="SKIP"
        SKIP=$((SKIP + 1))
        continue
      fi
    fi
    test_ssh_combo "$host" "$target"
  done
  echo ""
done

# ============================================================
# Summary matrix
# ============================================================

echo "=== Results Matrix ==="
echo ""
printf "%-10s" "host\\target"
for t in "${ALL_ARCHS[@]}"; do
  printf "%-10s" "$t"
done
echo ""
printf "%s\n" "$(printf '%-10s' '----------' '----------' '----------' '----------' '----------')"

for h in "${ALL_ARCHS[@]}"; do
  # Only show rows for tested hosts
  show=0
  for hh in "${HOSTS[@]}"; do
    if [[ "$hh" == "$h" ]]; then show=1; fi
  done
  if [[ $show -eq 0 ]]; then continue; fi

  printf "%-10s" "$h"
  for t in "${ALL_ARCHS[@]}"; do
    key="${h}_${t}"
    r="${RESULTS[$key]:-}"
    if [[ -z "$r" ]]; then
      printf "%-10s" "-"
    elif [[ "$r" == "PASS" ]]; then
      printf "%-10s" "PASS"
    elif [[ "$r" == "SKIP" ]]; then
      printf "%-10s" "skip"
    else
      printf "%-10s" "FAIL"
    fi
  done
  echo ""
done

echo ""
echo "=== Summary: ${PASS} pass, ${FAIL} fail, ${SKIP} skip / ${TOTAL} total ==="

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
