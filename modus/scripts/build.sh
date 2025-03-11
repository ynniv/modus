#!/bin/bash
# Build the Modus bootable image

set -e
cd "$(dirname "$0")/../.."
MODUS_DIR="$(pwd)"

OUTPUT=${1:-"modus/modus.img"}
if [[ "$OUTPUT" != /* ]]; then
    OUTPUT="$MODUS_DIR/$OUTPUT"
fi

echo "======================================"
echo "Building Modus"
echo "======================================"
echo "Output: $OUTPUT"
echo "======================================"

# Movitz needs to find its losp/ files relative to cwd
cd "$MODUS_DIR/lib/movitz"

sbcl --non-interactive \
     --eval "(require :asdf)" \
     --eval "(asdf:clear-source-registry)" \
     --eval "(setf asdf:*central-registry* (append (list #P\"$MODUS_DIR/lib/binary-types/\" #P\"$MODUS_DIR/lib/movitz/\" #P\"$MODUS_DIR/modus/build/\") asdf:*central-registry*))" \
     --eval "(asdf:load-system :binary-types)" \
     --eval "(asdf:load-system :movitz)" \
     --eval "(movitz:create-image)" \
     --eval "(movitz:dump-image :path \"$OUTPUT\" :qemu-align :hd)"

echo "======================================"
echo "Build successful: $OUTPUT"
echo "Run with: ./modus/scripts/run.sh"
echo "======================================"
