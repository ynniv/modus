#!/bin/bash
# make-sdcard-bootloader.sh - Create SD card with UART bootloader for Pi Zero 2 W
#
# This builds a permanent bootloader kernel that:
#   1. On boot, waits ~2s for a kernel upload over UART (magic byte 0x55)
#   2. If upload received: loads kernel to 0x300000 and jumps to it
#   3. If timeout: falls through to built-in SSH server
#
# Flash this SD card ONCE. Then deploy new kernels from Pi 5:
#   python3 scripts/deploy-kernel.py /path/to/kernel8.img
#
# Write to micro-SD with: sudo dd if=/tmp/pizero2w-sdcard.img of=/dev/sdX bs=4M

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT_DIR="/tmp/piboot"
IMG="/tmp/pizero2w-sdcard.img"

# Build bootloader kernel (includes SSH fallback)
echo "=== Building UART bootloader kernel ==="
cd "$SCRIPT_DIR"
sbcl --script mvm/build-uart-bootloader.lisp

# Create 16MB disk image with MBR + FAT16 partition
echo "=== Creating SD card image ==="
dd if=/dev/zero of="$IMG" bs=1M count=16 2>/dev/null

# Write MBR partition table
printf '\xeb\xfe' | dd of="$IMG" bs=1 conv=notrunc 2>/dev/null
printf '\x55\xaa' | dd of="$IMG" bs=1 seek=510 conv=notrunc 2>/dev/null
printf '\x80' | dd of="$IMG" bs=1 seek=446 conv=notrunc 2>/dev/null
printf '\x0c' | dd of="$IMG" bs=1 seek=450 conv=notrunc 2>/dev/null
printf '\x00\x08\x00\x00' | dd of="$IMG" bs=1 seek=454 conv=notrunc 2>/dev/null
printf '\x00\x78\x00\x00' | dd of="$IMG" bs=1 seek=458 conv=notrunc 2>/dev/null

# Format partition as FAT16
PART_IMG="/tmp/pizero2w-part.img"
dd if=/dev/zero of="$PART_IMG" bs=512 count=30720 2>/dev/null
/sbin/mkfs.vfat -F 16 -n PIBOOT "$PART_IMG" >/dev/null 2>&1

# config.txt
CFGTMP="/tmp/pizero2w-config.txt"
cat > "$CFGTMP" <<'EOF'
arm_64bit=1
kernel=kernel8.img
core_freq=250
enable_uart=1
init_uart_baud=115200
device_tree=
disable_commandline_tags=1
gpu_mem=16
start_file=start_cd.elf
fixup_file=fixup_cd.dat
EOF

# Copy files using mtools (no root/mount needed)
export MTOOLS_SKIP_CHECK=1
mcopy -i "$PART_IMG" "$BOOT_DIR/bootcode.bin" ::bootcode.bin
mcopy -i "$PART_IMG" "$BOOT_DIR/start_cd.elf" ::start_cd.elf
mcopy -i "$PART_IMG" "$BOOT_DIR/fixup_cd.dat" ::fixup_cd.dat
mcopy -i "$PART_IMG" "$BOOT_DIR/kernel8.img" ::kernel8.img
mcopy -i "$PART_IMG" "$CFGTMP" ::config.txt
rm "$CFGTMP"

# Insert partition into disk image
dd if="$PART_IMG" of="$IMG" bs=512 seek=2048 conv=notrunc 2>/dev/null
rm "$PART_IMG"

echo ""
echo "=== SD card image ready ==="
echo "Image: $IMG ($(du -h "$IMG" | cut -f1))"
echo ""
echo "Files in image:"
mdir -i "$IMG"@@$((2048*512)) 2>/dev/null || echo "  (use mdir to inspect)"
echo ""
echo "Write to micro-SD card (ONE TIME):"
echo "  sudo dd if=$IMG of=/dev/sdX bs=4M status=progress"
echo ""
echo "Then deploy new kernels over UART from Pi 5:"
echo "  python3 scripts/deploy-kernel.py /path/to/kernel8.img"
