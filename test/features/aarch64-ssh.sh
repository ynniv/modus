#!/bin/bash
# Test: AArch64 QEMU virt — SSH server boots
TEST_NAME="aarch64-ssh"
source "$(dirname "$0")/lib.sh"

TIMEOUT=120

echo "Building AArch64 SSH kernel..."
sbcl --script mvm/build-aarch64-ssh.lisp > /dev/null 2>&1

boot_aarch64_virt /tmp/modus64-aarch64-ssh.bin \
    -device 'e1000,netdev=net0,romfile=,rombar=0' \
    -netdev "user,id=net0"
wait_for "SSH:" 120
pass
