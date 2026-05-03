#!/usr/bin/env bash
# Build test fixture SO files for ARM64
# Requires: clang or aarch64-linux-gnu-gcc cross-compiler

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try cross-compiler first, then native clang
if command -v aarch64-linux-gnu-gcc &>/dev/null; then
    CC="aarch64-linux-gnu-gcc"
elif command -v clang &>/dev/null; then
    CC="clang --target=aarch64-linux-gnu"
else
    echo "Warning: No ARM64 cross-compiler found. Building native SO files."
    CC="gcc"
fi

echo "Using compiler: $CC"
echo "Building test fixtures..."

$CC -shared -fPIC -O0 -o "$SCRIPT_DIR/simple_add.so" "$SCRIPT_DIR/simple_add.c"
$CC -shared -fPIC -O0 -o "$SCRIPT_DIR/jni_test.so" "$SCRIPT_DIR/jni_test.c"
$CC -shared -fPIC -O0 -o "$SCRIPT_DIR/overflow_test.so" "$SCRIPT_DIR/overflow_test.c"
$CC -shared -fPIC -O0 -o "$SCRIPT_DIR/uaf_test.so" "$SCRIPT_DIR/uaf_test.c"
$CC -shared -fPIC -O0 -o "$SCRIPT_DIR/double_free_test.so" "$SCRIPT_DIR/double_free_test.c"

echo "All fixtures built successfully."
