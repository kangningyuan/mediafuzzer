"""Basic block coverage collection and feedback for fuzzing."""

import logging
from typing import Any

from config.settings import settings

logger = logging.getLogger("mediafuzzer.fuzzing.coverage")


class CoverageTracker:
    """AFL-style edge coverage tracker for Qiling emulation.

    Uses (prev_hash ^ curr_hash) % bitmap_size as edge index
    with hit count increment (cap at 255).
    """

    def __init__(self, bitmap_size: int | None = None) -> None:
        self.bitmap_size = bitmap_size or settings.COV_BITMAP_SIZE
        self.bitmap = bytearray(self.bitmap_size)
        self._prev_hash: int = 0
        self._covered_edges: set[int] = set()

    def on_basic_block(self, ql: Any, addr: int, size: int) -> None:
        """Hook callback for UC_HOOK_CODE / ql.hook_code.

        Computes edge index and updates bitmap with AFL-style hit count.
        """
        curr_hash = ((addr >> 4) ^ (addr << 8)) & 0xFFFFFFFF
        edge = (self._prev_hash ^ curr_hash) % self.bitmap_size

        # AFL-style hit count increment (cap at 255)
        if self.bitmap[edge] < 255:
            self.bitmap[edge] += 1

        self._covered_edges.add(edge)

        # ROR for next iteration
        self._prev_hash = ((curr_hash >> 1) | (curr_hash << 31)) & 0xFFFFFFFF

    def reset(self) -> None:
        """Reset bitmap and tracking state."""
        self.bitmap = bytearray(self.bitmap_size)
        self._prev_hash = 0
        self._covered_edges.clear()

    def get_new_edges(self, previous_bitmap: bytearray) -> set[int]:
        """Return edge indices that are new compared to previous_bitmap."""
        new = set()
        for i in range(self.bitmap_size):
            if self.bitmap[i] and not previous_bitmap[i]:
                new.add(i)
        return new

    @property
    def coverage_ratio(self) -> float:
        """Coverage ratio as a float between 0.0 and 1.0."""
        covered = sum(1 for b in self.bitmap if b)
        return covered / self.bitmap_size if self.bitmap_size else 0.0

    @property
    def covered_count(self) -> int:
        """Number of covered edges."""
        return sum(1 for b in self.bitmap if b)

    def register_hooks(self, emulated_func: Any) -> None:
        """Register coverage hooks on a Qiling instance.

        Args:
            emulated_func: EmulatedJNIFunc instance with .ql attribute
        """
        if emulated_func.ql is not None:
            emulated_func.ql.hook_code(self.on_basic_block)
            logger.debug("Coverage hooks registered on Qiling instance")
