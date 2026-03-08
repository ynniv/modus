#!/bin/bash
# lib.sh - Shared helpers for feature tests
#
# Source this from test scripts:
#   source "$(dirname "$0")/lib.sh"

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

TIMEOUT=${TEST_TIMEOUT:-60}
LOGFILE=$(mktemp /tmp/modus-test-XXXXXX.log)
QEMU_PID=""

cleanup() {
    if [ -n "$QEMU_PID" ]; then
        kill "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -f "$LOGFILE"
    exit "${1:-1}"
}
trap 'cleanup 1' INT TERM

pass() { echo "PASS: $TEST_NAME"; cleanup 0; }
fail() { echo "FAIL: $TEST_NAME — $1"; [ -f "$LOGFILE" ] && tail -20 "$LOGFILE"; cleanup 1; }

# Wait for a string to appear in the log file
wait_for() {
    local pattern="$1" timeout="${2:-$TIMEOUT}" tries=0
    while [ $tries -lt $((timeout * 2)) ]; do
        [ -n "$QEMU_PID" ] && ! kill -0 "$QEMU_PID" 2>/dev/null && fail "QEMU exited"
        grep -q "$pattern" "$LOGFILE" 2>/dev/null && return 0
        sleep 0.5
        tries=$((tries + 1))
    done
    fail "timeout waiting for '$pattern'"
}

# Boot QEMU in background, output to $LOGFILE
boot_x64() {
    local kernel="$1"; shift
    > "$LOGFILE"
    scripts/no-thp-exec qemu-system-x86_64 \
        -kernel "$kernel" -m 512 -nographic -no-reboot \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        "$@" > "$LOGFILE" 2>&1 &
    QEMU_PID=$!
}

boot_aarch64_virt() {
    local kernel="$1"; shift
    > "$LOGFILE"
    qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
        -kernel "$kernel" -nographic -semihosting \
        "$@" > "$LOGFILE" 2>&1 &
    QEMU_PID=$!
}

boot_rpi() {
    local kernel="$1"; shift
    > "$LOGFILE"
    qemu-system-aarch64 -machine raspi3b \
        -kernel "$kernel" -display none -serial stdio \
        "$@" > "$LOGFILE" 2>&1 &
    QEMU_PID=$!
}

# Send expression to REPL via stdin, check output
repl_eval() {
    local expr="$1" expected="$2"
    echo "$expr" > /proc/$QEMU_PID/fd/0 2>/dev/null || \
        fail "cannot write to QEMU stdin"
    sleep 2
    grep -q "$expected" "$LOGFILE" && return 0
    fail "expected '$expected' in output"
}

# Test SSH connectivity and eval (with retries for crypto init)
ssh_eval() {
    local port="$1" expr="$2" expected="$3"
    local result tries=0
    while [ $tries -lt 6 ]; do
        result=$(echo "$expr" | ssh -p "$port" -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
            test@localhost 2>/dev/null) && break
        tries=$((tries + 1))
        sleep 5
    done
    [ $tries -ge 6 ] && fail "SSH connection failed after retries"
    echo "$result" | grep -q "$expected" && return 0
    fail "SSH eval: expected '$expected', got '$result'"
}
