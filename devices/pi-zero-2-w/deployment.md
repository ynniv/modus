# Pi Zero 2 W Deployment (from Pi 5 host)

## Hardware Setup
- **Host**: Raspberry Pi 5 at modus-pi
- **Target**: Pi Zero 2 W
- **Wiring**: GPIO17 on Pi 5 header → RUN pin on Pi Zero 2 W
- **Serial**: /dev/ttyAMA0 at 115200 baud

## Deployment Scripts (on Pi 5)
Assumes an /etc/hosts entry for modus-pi

### `deploy-kernel.py`
UART bootloader deploy script:
1. Resets target via GPIO17
2. Waits for "RDY\n" bootloader signal
3. Sends magic byte (0x55), expects ACK (0xAA)
4. Sends 4-byte size (little-endian), then kernel data
5. Sends checksum, waits for response

```bash
python3 deploy-kernel.py /path/to/kernel8.img
```

### `pi5-reset-zero.sh`
Just resets the target:
```bash
./pi5-reset-zero.sh
# or
ssh modus@modus-pi './pi5-reset-zero.sh'
```

## Files on Pi 5
| File | Size | Modified |
|------|------|----------|
| `kernel8.img` | 677 KB | Mar 5 16:38 |
| `pizero2w-sdcard.img` | 16 MB | Mar 5 00:28 |
| `deploy-kernel.py` | 3.7 KB | Mar 5 00:49 |
| `pi5-reset-zero.sh` | 547 B | Mar 5 08:03 |

## Notes
- Requires pyserial and RPi.GPIO on the Pi 5
- Bootloader timeout is 10 seconds
- Transfer at 115200 baud (~10 bits/byte)
