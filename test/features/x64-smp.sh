#!/bin/bash
# Test: x86-64 QEMU — SMP multi-core boot
TEST_NAME="x64-smp"
source "$(dirname "$0")/lib.sh"

echo "Building x64 SSH kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus64)' \
     --eval '(modus64.build:build-kernel-mvm "/tmp/modus64.elf")' \
     --eval '(quit)' > /dev/null 2>&1

boot_x64 /tmp/modus64.elf -smp 4
wait_for ">"
pass
