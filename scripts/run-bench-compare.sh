#!/bin/bash
# run-bench-compare.sh - Compare Gen0 vs Gen1 benchmark performance
#
# Gen0: SBCL cross-compiled → MVM → native (build-bench.lisp)
# Gen1: Bare-metal MVM compiler (fixpoint Gen0 x64) → native
#
# Usage: ./scripts/run-bench-compare.sh [x64] [i386] [arm32] [aarch64]
# Default: x64 i386 arm32 aarch64

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$(dirname "$0")/.."

TARGETS="${@:-x64 i386 arm32 aarch64}"
TIMEOUT=${BENCH_TIMEOUT:-120}
FIXPOINT_TIMEOUT=${FIXPOINT_TIMEOUT:-300}

NO_THP="$SCRIPT_DIR/no-thp-exec"

echo "=== Modus Benchmark: Gen0 vs Gen1 ==="
echo "Targets: $TARGETS"
echo ""

# Architecture helpers
arch_id() {
  case "$1" in
    x64)     echo 0 ;;
    aarch64) echo 1 ;;
    i386)    echo 2 ;;
    arm32)   echo 3 ;;
  esac
}

metadata_file_offset() {
  case "$1" in
    x64)     echo 3670016  ;;  # 0x380000
    aarch64) echo 4194304  ;;  # 0x400000
    i386)    echo 3670016  ;;  # 0x380000
    arm32)   echo 4653056  ;;  # 0x470000
  esac
}

extract_pa() {
  case "$1" in
    x64)     echo 134217728  ;;  # 0x08000000
    aarch64) echo 1207959552 ;;  # 0x48000000
    i386)    echo 134217728  ;;  # 0x08000000
    arm32)   echo 134217728  ;;  # 0x08000000
  esac
}

image_extract_size() {
  case "$1" in
    x64)     echo 3670080  ;;
    aarch64) echo 4194368  ;;
    i386)    echo 3670080  ;;
    arm32)   echo 4653120  ;;
  esac
}

patch_u32_le() {
  local file=$1 offset=$2 value=$3
  local b0=$((value & 0xFF))
  local b1=$(( (value >> 8) & 0xFF ))
  local b2=$(( (value >> 16) & 0xFF ))
  local b3=$(( (value >> 24) & 0xFF ))
  printf "\\x$(printf '%02x' $b0)\\x$(printf '%02x' $b1)\\x$(printf '%02x' $b2)\\x$(printf '%02x' $b3)" | \
    dd of="$file" bs=1 seek="$offset" conv=notrunc 2>/dev/null
}

# Run a benchmark binary and wait for DONE, capturing wall-clock time.
# Uses timeout command to kill QEMU after TIMEOUT seconds.
# Returns: sets BENCH_MS to milliseconds or "TIMEOUT"/"FAIL"
run_bench_timed() {
  local arch=$1 kernel=$2 serial=$3 timeout_s=$4
  rm -f "$serial"
  touch "$serial"

  local start end
  start=$(date +%s%N)

  case "$arch" in
    x64)
      timeout "$timeout_s" "$NO_THP" qemu-system-x86_64 -kernel "$kernel" -m 512 \
        -display none -serial "file:$serial" -no-reboot 2>/dev/null &
      ;;
    aarch64)
      timeout "$timeout_s" "$NO_THP" qemu-system-aarch64 -M virt -cpu cortex-a53 -m 512 \
        -kernel "$kernel" -display none -serial "file:$serial" -semihosting 2>/dev/null &
      ;;
    i386)
      timeout "$timeout_s" "$NO_THP" qemu-system-i386 -kernel "$kernel" -m 512 \
        -display none -serial "file:$serial" -no-reboot 2>/dev/null &
      ;;
    arm32)
      timeout "$timeout_s" "$NO_THP" qemu-system-arm -M raspi2b -m 1G -kernel "$kernel" \
        -display none -serial "file:$serial" -monitor none 2>/dev/null &
      ;;
  esac
  local pid=$!

  # Poll for DONE marker in serial output
  while ! grep -q "DONE" "$serial" 2>/dev/null; do
    # Check if QEMU process is still alive
    if ! kill -0 "$pid" 2>/dev/null; then
      # Process died without printing DONE
      BENCH_MS="FAIL"
      return 1
    fi
    sleep 0.2
  done

  end=$(date +%s%N)
  BENCH_MS=$(( (end - start) / 1000000 ))

  # Kill QEMU (it's in an infinite loop after DONE)
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 0
}

cleanup() {
  pkill -f "qemu-system.*modus-bench" 2>/dev/null || true
  pkill -f "qemu-system.*fixpoint-bench" 2>/dev/null || true
  rm -f /tmp/qmp-bench-compare.sock /tmp/bench-compare-serial.txt
}
trap cleanup EXIT

# ============================================================
# Phase 1: Build and run Gen0 benchmarks
# ============================================================

echo "=== Phase 1: Gen0 Benchmarks (SBCL cross-compiled) ==="
echo ""

for target in $TARGETS; do
  echo "  Building Gen0 $target..."
  sbcl --script mvm/build-bench.lisp "$target" 2>&1 | grep -E 'Wrote|error' || true
done
echo ""

declare -A GEN0_RESULTS
declare -A GEN0_TIMES

for target in $TARGETS; do
  BIN="/tmp/modus-bench-${target}.bin"
  if [ ! -f "$BIN" ]; then
    echo "  [$target] SKIP (no binary)"
    continue
  fi

  SERIAL="/tmp/bench-gen0-${target}.txt"
  echo -n "  Running Gen0 $target... "
  if run_bench_timed "$target" "$BIN" "$SERIAL" "$TIMEOUT"; then
    echo "${BENCH_MS}ms"
    GEN0_RESULTS[$target]="$SERIAL"
    GEN0_TIMES[$target]="$BENCH_MS"
  else
    echo "$BENCH_MS"
    GEN0_RESULTS[$target]=""
    GEN0_TIMES[$target]="-"
  fi
done

echo ""

# ============================================================
# Phase 2: Build fixpoint Gen0 and cross-compile Gen1 for each target
# ============================================================

echo "=== Phase 2: Gen1 Benchmarks (bare-metal cross-compiled) ==="
echo ""

echo "  Building fixpoint Gen0 (x64)..."
sbcl --script mvm/build-fixpoint.lisp 2>&1 | grep -E 'written|bytecode:|Functions:' || true
echo ""

GEN0_IMG="/tmp/fixpoint-gen0.elf"

declare -A GEN1_RESULTS
declare -A GEN1_TIMES

for target in $TARGETS; do
  echo "  Cross-compiling Gen1 $target..."

  SOCK="/tmp/qmp-bench-compare.sock"
  SERIAL="/tmp/bench-compare-serial.txt"
  GEN1_IMG="/tmp/fixpoint-bench-gen1-${target}.bin"

  cp "$GEN0_IMG" /tmp/fixpoint-bench-cross.bin
  MD_OFF=$(metadata_file_offset x64)
  TARGET_ID=$(arch_id "$target")
  patch_u32_le /tmp/fixpoint-bench-cross.bin $((MD_OFF + 52)) "$TARGET_ID"
  patch_u32_le /tmp/fixpoint-bench-cross.bin $((MD_OFF + 56)) 0

  rm -f "$SOCK" "$GEN1_IMG" "$SERIAL"

  timeout "$FIXPOINT_TIMEOUT" "$NO_THP" qemu-system-x86_64 \
    -kernel /tmp/fixpoint-bench-cross.bin -m 512 \
    -display none -serial "file:$SERIAL" -no-reboot \
    -qmp "unix:$SOCK,server=on,wait=off" 2>/dev/null &
  PID=$!

  # Wait for DONE
  ELAPSED=0
  while ! grep -q "DONE" "$SERIAL" 2>/dev/null; do
    if ! kill -0 "$PID" 2>/dev/null; then
      echo "    FAIL: cross-compile process died"
      GEN1_RESULTS[$target]=""
      GEN1_TIMES[$target]="-"
      continue 2
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [[ $ELAPSED -ge $FIXPOINT_TIMEOUT ]]; then
      echo "    TIMEOUT after ${FIXPOINT_TIMEOUT}s"
      kill "$PID" 2>/dev/null || true
      wait "$PID" 2>/dev/null || true
      GEN1_RESULTS[$target]=""
      GEN1_TIMES[$target]="-"
      continue 2
    fi
  done
  echo "    Cross-compiled in ${ELAPSED}s"

  # Extract Gen1 image via QMP
  ADDR=$(extract_pa x64)
  SIZE=$(image_extract_size "$target")
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
    'val': $ADDR, 'size': $SIZE, 'filename': '$GEN1_IMG'
}}).encode() + b'\n')
recv()
time.sleep(1)
s.sendall(json.dumps({'execute': 'quit'}).encode() + b'\n')
s.close()
" 2>/dev/null

  sleep 1
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  rm -f "$SERIAL"

  if [[ ! -f "$GEN1_IMG" ]]; then
    echo "    FAIL: Gen1 image not extracted"
    GEN1_RESULTS[$target]=""
    GEN1_TIMES[$target]="-"
    continue
  fi
  echo "    Gen1 image: $(wc -c < "$GEN1_IMG") bytes"

  # Patch mode=3 (bench) in Gen1 image
  MD_OFF=$(metadata_file_offset "$target")
  patch_u32_le "$GEN1_IMG" $((MD_OFF + 56)) 3

  # Run Gen1 benchmarks with timing
  GEN1_SERIAL="/tmp/bench-gen1-${target}.txt"
  echo -n "    Running Gen1 $target... "
  if run_bench_timed "$target" "$GEN1_IMG" "$GEN1_SERIAL" "$TIMEOUT"; then
    echo "${BENCH_MS}ms"
    GEN1_RESULTS[$target]="$GEN1_SERIAL"
    GEN1_TIMES[$target]="$BENCH_MS"
  else
    echo "$BENCH_MS"
    echo "    Output:"
    head -20 "$GEN1_SERIAL" 2>/dev/null || true
    GEN1_RESULTS[$target]=""
    GEN1_TIMES[$target]="-"
  fi
  echo ""
done

# ============================================================
# Phase 3: Print comparison table
# ============================================================

echo ""
echo "================================================================"
echo "  BENCHMARK COMPARISON: Gen0 (SBCL) vs Gen1 (bare-metal)"
echo "================================================================"
echo ""

BENCHES="FIB SIEVE TAK ASUM ACK XOR CONS DIV"

# Results table (correctness)
printf "%-10s" "ARCH"
for b in $BENCHES; do
  printf " %-9s" "$b"
done
echo ""
printf "%-10s" "----------"
for b in $BENCHES; do
  printf " %-9s" "---------"
done
echo ""

for target in $TARGETS; do
  for gen in G0 G1; do
    if [[ "$gen" == "G0" ]]; then
      FILE="${GEN0_RESULTS[$target]}"
    else
      FILE="${GEN1_RESULTS[$target]}"
    fi
    printf "%-10s" "$target/$gen"
    if [[ -n "$FILE" ]]; then
      for b in $BENCHES; do
        status=$(grep "^\[$b\]" "$FILE" 2>/dev/null | awk '{print $3}')
        if [[ "$status" == "OK" ]]; then
          printf " %-9s" "OK"
        elif [[ -n "$status" ]]; then
          printf " %-9s" "FAIL"
        else
          printf " %-9s" "-"
        fi
      done
    else
      for b in $BENCHES; do
        printf " %-9s" "SKIP"
      done
    fi
    echo ""
  done
  echo ""
done

# Wall-clock timing summary
echo "--- Wall-Clock Time (boot + all benchmarks) ---"
echo ""
printf "%-10s  %-12s  %-12s  %-8s\n" "ARCH" "Gen0" "Gen1" "Ratio"
printf "%-10s  %-12s  %-12s  %-8s\n" "----------" "------------" "------------" "--------"

for target in $TARGETS; do
  t0="${GEN0_TIMES[$target]}"
  t1="${GEN1_TIMES[$target]}"
  if [[ "$t0" != "-" && "$t1" != "-" && -n "$t0" && -n "$t1" ]]; then
    ratio=$(python3 -c "print(f'{$t1/$t0:.2f}x')" 2>/dev/null || echo "?")
    printf "%-10s  %-12s  %-12s  %-8s\n" "$target" "${t0}ms" "${t1}ms" "$ratio"
  else
    t0_display="${t0:-SKIP}"
    t1_display="${t1:-SKIP}"
    [[ "$t0_display" != "-" && "$t0_display" != "SKIP" ]] && t0_display="${t0_display}ms"
    [[ "$t1_display" != "-" && "$t1_display" != "SKIP" ]] && t1_display="${t1_display}ms"
    printf "%-10s  %-12s  %-12s  %-8s\n" "$target" "$t0_display" "$t1_display" "-"
  fi
done

echo ""
echo "Gen0 = SBCL cross-compiled, Gen1 = bare-metal self-hosted"
echo "Ratio = Gen1/Gen0 (>1.0 = Gen1 slower, <1.0 = Gen1 faster)"
echo ""
echo "Done."
