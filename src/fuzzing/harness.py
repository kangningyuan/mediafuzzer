"""LibFuzzer harness C source generation and compilation."""

import ctypes
import logging
import os
import subprocess
import tempfile

from config.settings import settings

logger = logging.getLogger("mediafuzzer.fuzzing.harness")

# C template for LibFuzzer harness
_HARNESS_TEMPLATE = r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef COV_BITMAP_SIZE
#define COV_BITMAP_SIZE {cov_bitmap_size}
#endif

typedef int (*fuzz_callback_t)(const uint8_t *data, size_t size);
static fuzz_callback_t g_fuzz_callback = NULL;

typedef size_t (*custom_mutator_t)(uint8_t *data, size_t size, size_t max_size, unsigned int seed);
static custom_mutator_t g_custom_mutator = NULL;

uint8_t __libfuzzer_extra_counters[COV_BITMAP_SIZE];

void set_fuzz_callback(fuzz_callback_t cb) {{
    g_fuzz_callback = cb;
}}

void set_custom_mutator(custom_mutator_t m) {{
    g_custom_mutator = m;
}}

void reset_coverage_bitmap(void) {{
    memset(__libfuzzer_extra_counters, 0, COV_BITMAP_SIZE);
}}

uint8_t *get_coverage_bitmap(void) {{
    return __libfuzzer_extra_counters;
}}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    reset_coverage_bitmap();
    if (g_fuzz_callback) {{
        return g_fuzz_callback(data, size);
    }}
    return 0;
}}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {{
    if (g_custom_mutator) {{
        return g_custom_mutator(data, size, max_size, seed);
    }}
    return size;
}}
"""


def generate_harness_source(
    func_name: str = "target_func",
    callback_symbol: str = "python_fuzz_callback",
    cov_bitmap_size: int | None = None,
) -> str:
    """Generate C source for LibFuzzer harness."""
    bitmap_size = cov_bitmap_size or settings.COV_BITMAP_SIZE
    return _HARNESS_TEMPLATE.format(
        cov_bitmap_size=bitmap_size,
    )


def compile_harness(harness_source: str, output_path: str) -> str:
    """Compile harness C source into a shared library.

    Uses: clang -shared -fPIC -fsanitize=fuzzer-no-link
    Returns the path to the compiled .so
    """
    clang = settings.CLANG_PATH

    # Write source to temp file
    source_path = output_path + ".c"
    with open(source_path, "w") as f:
        f.write(harness_source)

    cmd = [
        clang,
        "-shared",
        "-fPIC",
        "-fsanitize=fuzzer-no-link",
        "-O2",
        "-o", output_path,
        source_path,
    ]

    logger.debug("Compiling harness: %s", " ".join(cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Harness compilation failed:\n{result.stderr}"
        )

    # Clean up source file
    try:
        os.unlink(source_path)
    except OSError:
        pass

    logger.info("Harness compiled: %s", output_path)
    return output_path


# ctypes callback types
FUZZ_CALLBACK_TYPE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
CUSTOM_MUTATOR_TYPE = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint)


class HarnessBridge:
    """Load compiled harness .so via ctypes and manage Python callback bridging."""

    def __init__(self, harness_path: str) -> None:
        if not os.path.isfile(harness_path):
            raise FileNotFoundError(f"Harness not found: {harness_path}")

        self._lib = ctypes.CDLL(harness_path)
        self._callback = None
        self._mutator = None

        # Set up function signatures
        self._lib.set_fuzz_callback.argtypes = [FUZZ_CALLBACK_TYPE]
        self._lib.set_fuzz_callback.restype = None
        self._lib.set_custom_mutator.argtypes = [CUSTOM_MUTATOR_TYPE]
        self._lib.set_custom_mutator.restype = None
        self._lib.reset_coverage_bitmap.argtypes = []
        self._lib.reset_coverage_bitmap.restype = None
        self._lib.get_coverage_bitmap.argtypes = []
        self._lib.get_coverage_bitmap.restype = ctypes.POINTER(ctypes.c_uint8)
        self._lib.LLVMFuzzerTestOneInput.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        self._lib.LLVMFuzzerTestOneInput.restype = ctypes.c_int

    def set_callback(self, callback: ctypes._CFuncPtr) -> None:
        """Set the Python fuzz callback."""
        self._callback = callback
        self._lib.set_fuzz_callback(callback)

    def set_mutator(self, mutator: ctypes._CFuncPtr) -> None:
        """Set the Python custom mutator."""
        self._mutator = mutator
        self._lib.set_custom_mutator(mutator)

    def reset_coverage(self) -> None:
        """Reset the coverage bitmap."""
        self._lib.reset_coverage_bitmap()

    def get_coverage_bitmap(self) -> bytes:
        """Read the current coverage bitmap."""
        ptr = self._lib.get_coverage_bitmap()
        bitmap_size = settings.COV_BITMAP_SIZE
        return bytes(ctypes.string_at(ptr, bitmap_size))

    def run_one_input(self, data: bytes) -> int:
        """Execute LLVMFuzzerTestOneInput with given data."""
        buf = (ctypes.c_uint8 * len(data))(*data)
        return self._lib.LLVMFuzzerTestOneInput(buf, len(data))
