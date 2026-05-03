"""Tests for fuzzing module."""

import pytest

from src.fuzzing.coverage import CoverageTracker
from src.fuzzing.format_aware import FormatAwareMutator


class TestCoverageTracker:
    """Test coverage tracking."""

    def test_bitmap_initialized_zero(self):
        """Coverage bitmap starts all zero."""
        tracker = CoverageTracker(bitmap_size=1024)
        assert all(b == 0 for b in tracker.bitmap)
        assert tracker.coverage_ratio == 0.0

    def test_on_basic_block_updates_bitmap(self):
        """Basic block hook updates bitmap."""
        tracker = CoverageTracker(bitmap_size=1024)
        # Simulate two basic block visits
        tracker.on_basic_block(None, addr=0x1000, size=4)
        tracker.on_basic_block(None, addr=0x2000, size=4)
        assert tracker.covered_count > 0
        assert tracker.coverage_ratio > 0.0

    def test_reset_clears_bitmap(self):
        """Reset clears all coverage data."""
        tracker = CoverageTracker(bitmap_size=1024)
        tracker.on_basic_block(None, addr=0x1000, size=4)
        tracker.reset()
        assert all(b == 0 for b in tracker.bitmap)
        assert tracker.coverage_ratio == 0.0

    def test_get_new_edges(self):
        """New edge detection works."""
        tracker = CoverageTracker(bitmap_size=1024)
        prev = bytearray(1024)
        tracker.on_basic_block(None, addr=0x1000, size=4)
        new = tracker.get_new_edges(prev)
        assert len(new) > 0

        # No new edges if same bitmap
        new2 = tracker.get_new_edges(bytearray(tracker.bitmap))
        assert len(new2) == 0

    def test_hit_count_cap_at_255(self):
        """Hit count caps at 255."""
        tracker = CoverageTracker(bitmap_size=1024)
        for _ in range(300):
            tracker.on_basic_block(None, addr=0x1000, size=4)
            # Reset prev_hash to produce same edge
            tracker._prev_hash = 0
        # At least one entry should be 255
        assert 255 in tracker.bitmap


class TestFormatAwareMutator:
    """Test format-aware mutation."""

    def test_raw_mutation_changes_data(self):
        """Raw mutation changes the input data."""
        mutator = FormatAwareMutator(format_name=None)
        original = b"\x00" * 64
        mutated = mutator._raw_mutate(original, max_size=4096)
        assert mutated != original or len(mutated) != len(original)

    def test_gif_magic_preserved(self):
        """GIF format-aware mutation preserves magic bytes."""
        mutator = FormatAwareMutator(format_name="GIF")
        seed = mutator.generate_seed()
        mutated = mutator.mutate(seed, max_size=65536)
        assert bytes(mutated[:6]) == b"GIF89a"

    def test_jpeg_magic_preserved(self):
        """JPEG format-aware mutation preserves SOI marker."""
        mutator = FormatAwareMutator(format_name="JPEG")
        seed = mutator.generate_seed()
        mutated = mutator.mutate(seed, max_size=65536)
        assert bytes(mutated[:2]) == b"\xFF\xD8"

    def test_webp_magic_preserved(self):
        """WebP format-aware mutation preserves RIFF magic."""
        mutator = FormatAwareMutator(format_name="WebP")
        seed = mutator.generate_seed()
        mutated = mutator.mutate(seed, max_size=65536)
        assert bytes(mutated[:4]) == b"RIFF"

    def test_seed_generation_no_format(self):
        """Seed generation without format produces random bytes."""
        mutator = FormatAwareMutator(format_name=None)
        seed = mutator.generate_seed()
        assert len(seed) == 64

    def test_seed_generation_gif(self):
        """GIF seed starts with GIF89a."""
        mutator = FormatAwareMutator(format_name="GIF")
        seed = mutator.generate_seed()
        assert seed[:6] == b"GIF89a"

    def test_unknown_format_no_crash(self):
        """Unknown format name doesn't crash, falls back to raw mutation."""
        mutator = FormatAwareMutator(format_name="UNKNOWN_FORMAT")
        seed = b"\x00" * 64
        mutated = mutator.mutate(seed)
        assert len(mutated) > 0
