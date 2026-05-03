/**
 * LibFuzzer harness template for MediaFuzzer.
 *
 * This C source is compiled into a shared library and loaded by Python via ctypes.
 * It provides:
 *   - LLVMFuzzerTestOneInput: entry point that delegates to a Python callback
 *   - __libfuzzer_extra_counters: shared coverage bitmap
 *   - LLVMFuzzerCustomMutator: delegates to Python for format-aware mutation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Configuration placeholders — replaced at compile time */
#ifndef COV_BITMAP_SIZE
#define COV_BITMAP_SIZE 65536
#endif

/* Python callback type: returns 0=normal, -1=anomaly, 1=keep input */
typedef int (*fuzz_callback_t)(const uint8_t *data, size_t size);
static fuzz_callback_t g_fuzz_callback = NULL;

/* Custom mutator type: returns new size */
typedef size_t (*custom_mutator_t)(uint8_t *data, size_t size, size_t max_size, unsigned int seed);
static custom_mutator_t g_custom_mutator = NULL;

/* Shared coverage bitmap — LibFuzzer reads this for coverage guidance */
uint8_t __libfuzzer_extra_counters[COV_BITMAP_SIZE];

/* Set the Python fuzz callback */
void set_fuzz_callback(fuzz_callback_t cb) {
    g_fuzz_callback = cb;
}

/* Set the Python custom mutator */
void set_custom_mutator(custom_mutator_t m) {
    g_custom_mutator = m;
}

/* Reset the coverage bitmap to zero */
void reset_coverage_bitmap(void) {
    memset(__libfuzzer_extra_counters, 0, COV_BITMAP_SIZE);
}

/* Get pointer to the coverage bitmap */
uint8_t *get_coverage_bitmap(void) {
    return __libfuzzer_extra_counters;
}

/* LibFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    reset_coverage_bitmap();
    if (g_fuzz_callback) {
        return g_fuzz_callback(data, size);
    }
    return 0;
}

/* Custom mutator — delegates to Python if set, otherwise no-op */
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
    if (g_custom_mutator) {
        return g_custom_mutator(data, size, max_size, seed);
    }
    /* No-op: return size unchanged */
    return size;
}

/* Optional: custom crossover */
size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                  const uint8_t *data2, size_t size2,
                                  uint8_t *out, size_t max_out_size,
                                  unsigned int seed) {
    /* Simple alternating copy */
    size_t i = 0;
    size_t j1 = 0, j2 = 0;
    int pick = seed & 1;
    while (i < max_out_size && (j1 < size1 || j2 < size2)) {
        if (pick && j1 < size1) {
            out[i++] = data1[j1++];
        } else if (j2 < size2) {
            out[i++] = data2[j2++];
        } else if (j1 < size1) {
            out[i++] = data1[j1++];
        }
        pick = !pick;
    }
    return i;
}
