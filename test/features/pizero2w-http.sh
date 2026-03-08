#!/bin/bash
# Test: Pi Zero 2 W — HTTP server responds (requires real hardware)
TEST_NAME="pizero2w-http"
source "$(dirname "$0")/lib.sh"

PI_HOST=${PI_HOST:-10.0.0.2}

result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 \
    "http://${PI_HOST}/" 2>/dev/null) || true
[ "$result" = "200" ] || fail "HTTP returned $result, expected 200"
pass
