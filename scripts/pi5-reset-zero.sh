#!/bin/bash
# pi5-reset-zero.sh - Reset Pi Zero 2 W via GPIO 17 on Pi 5 host
#
# GPIO 17 on Pi 5 header → RUN pin on Pi Zero 2 W
# Pulse low for 100ms to reset, then release (input mode lets
# the Zero's internal pull-up bring RUN high again).
#
# Usage: ./pi5-reset-zero.sh
#        ssh modus@192.168.5.202 './pi5-reset-zero.sh'

set -e

echo "Resetting Pi Zero 2 W via GPIO 17..."
pinctrl set 17 op dl   # output, drive low
sleep 0.1
pinctrl set 17 ip pn   # input, no pull (Zero's pull-up restores RUN)
echo "Done. Pi Zero 2 W is rebooting."
