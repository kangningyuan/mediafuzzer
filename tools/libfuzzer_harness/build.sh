#!/usr/bin/env bash
# Build script for LibFuzzer harness
# Usage: ./build.sh [CLANG_PATH] [COV_BITMAP_SIZE]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

CLANG_PATH="${1:-}"
COV_BITMAP_SIZE="${2:-65536}"

# Validate Clang exists
if [ -n "$CLANG_PATH" ]; then
    export CLANG_PATH
elif ! command -v clang-18 &>/dev/null && ! command -v clang &>/dev/null; then
    echo "Error: No Clang compiler found. Install clang-18 or provide path as argument."
    exit 1
fi

echo "Building LibFuzzer harness..."
echo "  CLANG_PATH: ${CLANG_PATH:-auto-detect}"
echo "  COV_BITMAP_SIZE: ${COV_BITMAP_SIZE}"

rm -rf "$BUILD_DIR"
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" \
    -DCOV_BITMAP_SIZE="$COV_BITMAP_SIZE" \
    -DCMAKE_BUILD_TYPE=Release

cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "Build complete: ${BUILD_DIR}/libharness.so"
