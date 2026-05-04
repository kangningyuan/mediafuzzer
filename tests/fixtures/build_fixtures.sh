#!/usr/bin/env bash
# Build test fixture SO files for ARM64
# Requires: clang-18 with aarch64 target support (cross-compile without libc headers)
# Uses -nostdlib + unresolved symbol tolerance; malloc/free/memcpy resolved by Qiling rootfs at runtime

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer clang-18 with aarch64 target (no ARM64 libc headers needed)
if command -v clang-18 &>/dev/null; then
    CC="clang-18 --target=aarch64-linux-gnu"
elif command -v aarch64-linux-gnu-gcc &>/dev/null; then
    CC="aarch64-linux-gnu-gcc"
elif command -v clang &>/dev/null; then
    CC="clang --target=aarch64-linux-gnu"
else
    echo "Error: No ARM64 cross-compiler found (need clang-18, clang, or aarch64-linux-gnu-gcc)."
    exit 1
fi

echo "Using compiler: $CC"
echo "Building test fixtures..."

# simple_add.c has no libc dependencies
$CC -shared -fPIC -O0 -nostdlib \
    -o "$SCRIPT_DIR/simple_add.so" "$SCRIPT_DIR/simple_add.c"

# The rest use malloc/free/memcpy — declared in-source, linked at runtime by Qiling
for src in jni_test overflow_test uaf_test double_free_test; do
    $CC -shared -fPIC -O0 -nostdlib \
        -Wl,--unresolved-symbols=ignore-all \
        -o "$SCRIPT_DIR/${src}.so" "$SCRIPT_DIR/${src}.c"
done

echo "All fixtures built successfully."
