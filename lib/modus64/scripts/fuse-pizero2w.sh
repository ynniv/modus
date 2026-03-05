#!/bin/bash
# fuse-pizero2w.sh - Create SD card image that enables USB boot on Pi Zero 2 W
#
# The Pi Zero 2 W ships with USB boot disabled in OTP. This creates a
# minimal SD card image that programs the fuse on first boot. One-time,
# irreversible — after this, the Pi always tries USB boot when no SD
# card is present.
#
# Usage:
#   ./scripts/fuse-pizero2w.sh
#   sudo dd if=/tmp/pizero2w-fuse.img of=/dev/sdX bs=4M status=progress
#   # Insert SD into Pi Zero 2 W, power on, wait 5s, power off, remove SD.
#   # USB boot is now permanently enabled.

set -e

BOOT_DIR="/tmp/piboot"
IMG="/tmp/pizero2w-fuse.img"

die() { echo "ERROR: $*" >&2; exit 1; }

# --- Prerequisites ---
command -v mcopy >/dev/null     || die "mtools not found (apt install mtools)"
command -v mkfs.vfat >/dev/null || die "mkfs.vfat not found (apt install dosfstools)"
[ -f "$BOOT_DIR/bootcode.bin" ] || die "bootcode.bin not in $BOOT_DIR"
[ -f "$BOOT_DIR/start_cd.elf" ] || die "start_cd.elf not in $BOOT_DIR"
[ -f "$BOOT_DIR/fixup_cd.dat" ] || die "fixup_cd.dat not in $BOOT_DIR"

# --- Create minimal 8MB disk image ---
echo "Creating USB boot fuse image..."
dd if=/dev/zero of="$IMG" bs=1M count=8 2>/dev/null

# MBR: boot signature + one active FAT partition at sector 2048
printf '\xeb\xfe'          | dd of="$IMG" bs=1 conv=notrunc 2>/dev/null
printf '\x55\xaa'          | dd of="$IMG" bs=1 seek=510 conv=notrunc 2>/dev/null
printf '\x80'              | dd of="$IMG" bs=1 seek=446 conv=notrunc 2>/dev/null
printf '\x0c'              | dd of="$IMG" bs=1 seek=450 conv=notrunc 2>/dev/null
printf '\x00\x08\x00\x00' | dd of="$IMG" bs=1 seek=454 conv=notrunc 2>/dev/null
printf '\x00\x38\x00\x00' | dd of="$IMG" bs=1 seek=458 conv=notrunc 2>/dev/null

# Format partition
PART_IMG=$(mktemp)
dd if=/dev/zero of="$PART_IMG" bs=512 count=14336 2>/dev/null
/sbin/mkfs.vfat -F 16 -n FUSE "$PART_IMG" >/dev/null 2>&1

# config.txt: program the OTP fuse + minimal kernel config
CFGTMP=$(mktemp)
cat > "$CFGTMP" <<'EOF'
# Pi Zero 2 W - program USB boot OTP fuse
# Boot this SD card ONCE then remove it.
arm_64bit=1
core_freq=250
gpu_mem=16
start_file=start_cd.elf
fixup_file=fixup_cd.dat
program_usb_boot_mode=1
EOF

# Copy GPU firmware + config (no kernel needed — GPU programs OTP before kernel)
export MTOOLS_SKIP_CHECK=1
mcopy -i "$PART_IMG" "$BOOT_DIR/bootcode.bin" ::bootcode.bin
mcopy -i "$PART_IMG" "$BOOT_DIR/start_cd.elf" ::start_cd.elf
mcopy -i "$PART_IMG" "$BOOT_DIR/fixup_cd.dat" ::fixup_cd.dat
mcopy -i "$PART_IMG" "$CFGTMP"                ::config.txt
rm "$CFGTMP"

# Assemble disk image
dd if="$PART_IMG" of="$IMG" bs=512 seek=2048 conv=notrunc 2>/dev/null
rm "$PART_IMG"

echo ""
echo "Fuse image: $IMG ($(stat -c '%s bytes' "$IMG"))"
echo ""
echo "Flash to micro-SD:"
echo "  sudo dd if=$IMG of=/dev/sdX bs=4M status=progress"
echo ""
echo "Then:"
echo "  1. Insert SD into Pi Zero 2 W"
echo "  2. Power on (green LED blinks — GPU programs OTP fuse)"
echo "  3. Wait 5 seconds, power off"
echo "  4. Remove SD card"
echo ""
echo "USB boot is now permanently enabled. Deploy kernels with:"
echo "  ./scripts/boot-pizero2w.sh"
