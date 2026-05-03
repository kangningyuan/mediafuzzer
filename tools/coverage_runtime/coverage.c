/**
 * Coverage instrumentation runtime for Qiling hook integration.
 *
 * Provides basic block coverage tracking compatible with
 * __libfuzzer_extra_counters shared bitmap.
 */

#include <stdint.h>
#include <string.h>

#ifndef COV_BITMAP_SIZE
#define COV_BITMAP_SIZE 65536
#endif

/* Shared coverage bitmap */
static uint8_t cov_bitmap[COV_BITMAP_SIZE];

/* Previous basic block hash for edge coverage */
static uint32_t prev_hash = 0;

/* ROR32 helper */
static inline uint32_t ror32(uint32_t val, unsigned int n) {
    n &= 31;
    return (val >> n) | (val << (32 - n));
}

/**
 * Record a basic block hit.
 * Computes edge index using (prev_hash ^ curr_hash) % COV_BITMAP_SIZE
 * and applies AFL-style hit count increment (cap at 255).
 */
void cov_trace_pc(uintptr_t pc) {
    uint32_t curr_hash = (uint32_t)((pc >> 4) ^ (pc << 8));
    uint32_t edge = (prev_hash ^ curr_hash) % COV_BITMAP_SIZE;

    /* AFL-style hit count increment */
    uint8_t old = cov_bitmap[edge];
    if (old < 255) {
        cov_bitmap[edge] = old + 1;
    }

    prev_hash = ror32(curr_hash, 1);
}

/* Reset coverage bitmap and previous hash */
void cov_reset(void) {
    memset(cov_bitmap, 0, COV_BITMAP_SIZE);
    prev_hash = 0;
}

/* Count covered entries (non-zero) */
uint32_t cov_get_covered_count(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < COV_BITMAP_SIZE; i++) {
        if (cov_bitmap[i]) count++;
    }
    return count;
}

/* Coverage as per-mille */
uint32_t cov_get_coverage_per_mille(void) {
    return (cov_get_covered_count() * 1000) / COV_BITMAP_SIZE;
}

/* Get pointer to bitmap for external reading */
uint8_t *cov_get_bitmap(void) {
    return cov_bitmap;
}
