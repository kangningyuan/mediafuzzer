"""File format-aware mutation for fuzzing."""

import logging
import os
import random
from typing import Any

from config.file_formats import get_format, FormatSkeleton

logger = logging.getLogger("mediafuzzer.fuzzing.format_aware")


class FormatAwareMutator:
    """Mutation strategy that preserves format skeleton structure.

    After standard mutation, restores all fixed=True fields and magic bytes
    from the format skeleton.
    """

    def __init__(self, format_name: str | None = None) -> None:
        self.format_name = format_name
        self.skeleton: FormatSkeleton | None = None
        if format_name:
            try:
                self.skeleton = get_format(format_name)
            except KeyError:
                logger.warning("Unknown format '%s', mutation will be format-unaware", format_name)

    def mutate(self, data: bytes, max_size: int = 4096, seed: int | None = None) -> bytearray:
        """Apply format-aware mutation.

        Strategy:
        1. Standard raw mutation
        2. Restore all fixed=True fields from skeleton
        3. Restore magic bytes
        """
        if seed is not None:
            random.seed(seed)

        buf = self._raw_mutate(data, max_size, seed)

        if self.skeleton:
            # Restore fixed fields
            for field_def in self.skeleton.fields:
                if field_def.fixed and field_def.default_value:
                    start = field_def.offset
                    end = start + field_def.size
                    if end <= len(buf):
                        buf[start:end] = field_def.default_value

            # Restore magic bytes
            magic = self.skeleton.magic
            if len(buf) >= len(magic):
                buf[:len(magic)] = magic

        return buf

    def _raw_mutate(self, data: bytes, max_size: int, seed: int | None = None) -> bytearray:
        """Apply standard mutation operations with probabilistic selection.

        Operations and probabilities:
        - Random byte replacement (0.4)
        - Bit flip (0.15)
        - Arithmetic increment/decrement (0.15)
        - Block copy (0.1)
        - Byte insertion (0.1)
        - Byte deletion (0.05)
        - Crossover (0.05)
        """
        if not data:
            return bytearray(self.generate_seed())

        buf = bytearray(data)

        # Perform 1-4 mutation operations
        num_ops = random.randint(1, 4)
        for _ in range(num_ops):
            r = random.random()

            if r < 0.4:
                # Random byte replacement
                if buf:
                    pos = random.randint(0, len(buf) - 1)
                    buf[pos] = random.randint(0, 255)

            elif r < 0.55:
                # Bit flip
                if buf:
                    pos = random.randint(0, len(buf) - 1)
                    bit = 1 << random.randint(0, 7)
                    buf[pos] ^= bit

            elif r < 0.7:
                # Arithmetic increment/decrement
                if buf:
                    pos = random.randint(0, len(buf) - 1)
                    delta = random.choice([-35, -1, 1, 35])
                    buf[pos] = (buf[pos] + delta) & 0xFF

            elif r < 0.8:
                # Block copy (repeat a chunk)
                if len(buf) > 4:
                    src_start = random.randint(0, len(buf) - 2)
                    src_end = random.randint(src_start + 1, min(src_start + 32, len(buf)))
                    block = buf[src_start:src_end]
                    dst_start = random.randint(0, max(len(buf) - len(block), 0))
                    for i, b in enumerate(block):
                        if dst_start + i < len(buf):
                            buf[dst_start + i] = b

            elif r < 0.9:
                # Byte insertion
                if len(buf) < max_size:
                    pos = random.randint(0, len(buf))
                    buf.insert(pos, random.randint(0, 255))

            elif r < 0.95:
                # Byte deletion
                if len(buf) > 1:
                    pos = random.randint(0, len(buf) - 1)
                    buf.pop(pos)

            else:
                # Crossover with a different seed
                other = self.generate_seed()
                if buf and other:
                    cross_point = random.randint(0, min(len(buf), len(other)) - 1)
                    for i in range(cross_point, min(len(buf), len(other))):
                        buf[i] = other[i]

        # Truncate to max_size
        if len(buf) > max_size:
            buf = buf[:max_size]

        return buf

    def generate_seed(self) -> bytes:
        """Generate a seed using the format skeleton, or random bytes."""
        if self.skeleton:
            return self.skeleton.generate_seed()
        return os.urandom(64)
