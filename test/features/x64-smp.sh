#!/bin/bash
# Test: x86-64 QEMU — SMP multi-core boot
TEST_NAME="x64-smp"
source "$(dirname "$0")/lib.sh"

echo "Building x64 SSH kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus)' \
     --eval '(modus.build:build-kernel-mvm "/tmp/modus.elf")' \
     --eval '(quit)' > /dev/null 2>&1

boot_x64 /tmp/modus.elf -smp 4
wait_for ">"
pass
