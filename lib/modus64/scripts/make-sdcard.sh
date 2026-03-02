#!/bin/bash
# make-sdcard.sh - Create an SD card image for Pi Zero 2 W bare metal boot
#
# Creates a small FAT32 image with bootcode.bin, GPU firmware, and kernel.
# Write to micro-SD with: dd if=pizero2w-sdcard.img of=/dev/sdX bs=4M status=progress
#
# This bypasses the BCM2837A0 USB boot ROM bug by using SD card boot instead.
# The USB port is then free for DWC2 CDC-ECM gadget mode (our SSH driver).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT_DIR="/tmp/piboot"
IMG="/tmp/pizero2w-sdcard.img"

# Build kernel first
echo "=== Building kernel ==="
cd "$SCRIPT_DIR"
sbcl --script mvm/build-pizero2w-ssh.lisp

# Create 8MB disk image with MBR + FAT32 partition
echo "=== Creating SD card image ==="
dd if=/dev/zero of="$IMG" bs=1M count=16 2>/dev/null

# Write MBR partition table: one FAT32 partition from sector 2048 to end
# Partition type 0x0C = FAT32 LBA
printf '\xeb\xfe' | dd of="$IMG" bs=1 conv=notrunc 2>/dev/null  # boot jump
printf '\x55\xaa' | dd of="$IMG" bs=1 seek=510 conv=notrunc 2>/dev/null  # MBR sig
# Partition entry 1 at offset 446: active, type=0x0C, start=2048, size=14336
printf '\x80' | dd of="$IMG" bs=1 seek=446 conv=notrunc 2>/dev/null  # active
printf '\x0c' | dd of="$IMG" bs=1 seek=450 conv=notrunc 2>/dev/null  # type FAT32 LBA
printf '\x00\x08\x00\x00' | dd of="$IMG" bs=1 seek=454 conv=notrunc 2>/dev/null  # LBA start=2048
printf '\x00\x78\x00\x00' | dd of="$IMG" bs=1 seek=458 conv=notrunc 2>/dev/null  # size=30720

# Format the partition as FAT32 using mtools
# Create a separate FAT image for the partition area
PART_IMG="/tmp/pizero2w-part.img"
dd if=/dev/zero of="$PART_IMG" bs=512 count=30720 2>/dev/null
/sbin/mkfs.vfat -F 16 -n PIBOOT "$PART_IMG" >/dev/null 2>&1

# Write config.txt
CFGTMP="/tmp/pizero2w-config.txt"
cat > "$CFGTMP" <<'EOF'
# Pi Zero 2 W - bare metal kernel (SD card boot)
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

# Insert partition into disk image at sector 2048
dd if="$PART_IMG" of="$IMG" bs=512 seek=2048 conv=notrunc 2>/dev/null
rm "$PART_IMG"

echo ""
echo "=== SD card image ready ==="
echo "Image: $IMG ($(du -h "$IMG" | cut -f1))"
echo ""
echo "Files in image:"
mdir -i "$IMG"@@$((2048*512)) 2>/dev/null || echo "  (use mdir to inspect)"
echo ""
echo "Write to micro-SD card:"
echo "  sudo dd if=$IMG of=/dev/sdX bs=4M status=progress"
echo ""
echo "Then insert into Pi Zero 2 W and power on."
echo "After boot, configure host network:"
echo '  IFACE=$(ip -o link | grep -i 02:00:00:00:00:01 | awk -F'"'"'[: ]'"'"' '"'"'{print $3}'"'"')'
echo '  sudo ip addr add 10.0.0.1/24 dev "$IFACE"'
echo '  sudo ip link set "$IFACE" up'
echo "  ssh test@10.0.0.2"
