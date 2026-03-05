#!/bin/bash
# build-pizero2w.sh - Build Pi Zero 2 W kernel and SD card image
#
# Creates /tmp/pizero2w.img — a 16MB FAT16 SD card image with:
#   bootcode.bin, start_cd.elf, fixup_cd.dat, config.txt, kernel8.img
#
# Usage: ./scripts/build-pizero2w.sh [--no-actors]
#
# Flash:  sudo dd if=/tmp/pizero2w.img of=/dev/sdX bs=4M status=progress
# Boot:   ./scripts/boot-pizero2w.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT_DIR="/tmp/piboot"
IMG="/tmp/pizero2w.img"

die() { echo "ERROR: $*" >&2; exit 1; }

# Actors by default
BUILD_SCRIPT="mvm/build-pizero2w-actors.lisp"
if [ "${1:-}" = "--no-actors" ]; then
    BUILD_SCRIPT="mvm/build-pizero2w-ssh.lisp"
fi

# --- Prerequisites ---
command -v sbcl >/dev/null    || die "sbcl not found"
command -v mcopy >/dev/null   || die "mtools not found (apt install mtools)"
command -v mkfs.vfat >/dev/null || die "mkfs.vfat not found (apt install dosfstools)"
[ -f "$BOOT_DIR/bootcode.bin" ] || die "bootcode.bin not in $BOOT_DIR"
[ -f "$BOOT_DIR/start_cd.elf" ] || die "start_cd.elf not in $BOOT_DIR"
[ -f "$BOOT_DIR/fixup_cd.dat" ] || die "fixup_cd.dat not in $BOOT_DIR"

# --- Build kernel ---
echo "Building kernel..."
cd "$SCRIPT_DIR"
sbcl --noinform --script "$BUILD_SCRIPT"

# --- Create 16MB disk image with MBR + FAT16 partition ---
echo "Creating SD card image..."
dd if=/dev/zero of="$IMG" bs=1M count=16 2>/dev/null

# MBR: boot signature + one active FAT32-LBA partition at sector 2048
printf '\xeb\xfe'             | dd of="$IMG" bs=1 conv=notrunc 2>/dev/null
printf '\x55\xaa'             | dd of="$IMG" bs=1 seek=510 conv=notrunc 2>/dev/null
printf '\x80'                 | dd of="$IMG" bs=1 seek=446 conv=notrunc 2>/dev/null
printf '\x0c'                 | dd of="$IMG" bs=1 seek=450 conv=notrunc 2>/dev/null
printf '\x00\x08\x00\x00'    | dd of="$IMG" bs=1 seek=454 conv=notrunc 2>/dev/null
printf '\x00\x78\x00\x00'    | dd of="$IMG" bs=1 seek=458 conv=notrunc 2>/dev/null

# Format partition
PART_IMG="/tmp/pizero2w-part.img"
dd if=/dev/zero of="$PART_IMG" bs=512 count=30720 2>/dev/null
/sbin/mkfs.vfat -F 16 -n PIBOOT "$PART_IMG" >/dev/null 2>&1

# config.txt for bare-metal kernel
CFGTMP=$(mktemp)
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

# Copy files into partition (no root/mount needed)
export MTOOLS_SKIP_CHECK=1
mcopy -i "$PART_IMG" "$BOOT_DIR/bootcode.bin"  ::bootcode.bin
mcopy -i "$PART_IMG" "$BOOT_DIR/start_cd.elf"  ::start_cd.elf
mcopy -i "$PART_IMG" "$BOOT_DIR/fixup_cd.dat"  ::fixup_cd.dat
mcopy -i "$PART_IMG" "$BOOT_DIR/kernel8.img"   ::kernel8.img
mcopy -i "$PART_IMG" "$CFGTMP"                  ::config.txt
rm "$CFGTMP"

# Assemble disk image
dd if="$PART_IMG" of="$IMG" bs=512 seek=2048 conv=notrunc 2>/dev/null
rm "$PART_IMG"

# --- Done ---
echo ""
echo "SD card image: $IMG ($(stat -c '%s bytes' "$IMG"))"
echo ""
echo "Flash to micro-SD:"
echo "  sudo dd if=$IMG of=/dev/sdX bs=4M status=progress"
echo ""
echo "Then insert SD, plug USB into host, and run:"
echo "  ./scripts/boot-pizero2w.sh"
