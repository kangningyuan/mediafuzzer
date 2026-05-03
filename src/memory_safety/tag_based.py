"""Tagged pointer-based proactive memory safety detection."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from config.settings import settings

logger = logging.getLogger("mediafuzzer.memory_safety.tag_based")

# ARM64 tagged pointer constants
TAG_BITS = settings.MEM_TAG_BITS  # 16
TAG_MASK = 0xFFFF << 48
ADDR_MASK = (1 << 48) - 1


@dataclass
class MemBlock:
    """Represents a tracked memory allocation."""

    base_addr: int
    size: int
    tag: int  # 16-bit tag
    freed: bool = False
    alloc_caller: int = 0
    free_caller: int = 0
    alloc_time: float = 0.0
    free_time: float = 0.0


class MemoryStateTable:
    """Tracks all memory allocations and their metadata."""

    def __init__(self) -> None:
        self._blocks: dict[int, MemBlock] = {}  # base_addr -> MemBlock
        self._tag_index: dict[int, list[int]] = {}  # tag -> list of base_addrs

    def allocate(self, size: int, caller_addr: int = 0) -> tuple[int, int]:
        """Record a new allocation. Returns (tagged_ptr, tag)."""
        tag = _generate_tag()
        # In real usage, the caller provides base_addr from Qiling mem.map
        # Here we just record with tag
        return 0, tag

    def add_block(self, base_addr: int, size: int, tag: int, caller_addr: int = 0) -> MemBlock:
        """Add a memory block to the tracking table."""
        block = MemBlock(
            base_addr=base_addr,
            size=size,
            tag=tag,
            alloc_caller=caller_addr,
            alloc_time=time.monotonic(),
        )
        self._blocks[base_addr] = block

        if tag not in self._tag_index:
            self._tag_index[tag] = []
        self._tag_index[tag].append(base_addr)

        return block

    def lookup(self, addr: int) -> MemBlock | None:
        """Look up the memory block containing the given address."""
        real_addr = addr & ADDR_MASK
        # Find the block whose range contains this address
        for base, block in self._blocks.items():
            if block.base_addr <= real_addr < block.base_addr + block.size:
                return block
        return None

    def lookup_by_base(self, base_addr: int) -> MemBlock | None:
        """Look up a block by its exact base address."""
        return self._blocks.get(base_addr)

    def find_by_tag(self, tag: int) -> MemBlock | None:
        """Find a block by its tag. Returns the first match."""
        addrs = self._tag_index.get(tag, [])
        if addrs:
            return self._blocks.get(addrs[0])
        return None

    def free(self, addr: int, caller_addr: int = 0) -> MemBlock | None:
        """Mark a block as freed. Returns the block or None."""
        real_addr = addr & ADDR_MASK
        block = self.lookup(real_addr)
        if block is None:
            return None
        block.freed = True
        block.free_caller = caller_addr
        block.free_time = time.monotonic()
        return block

    def clear(self) -> None:
        """Clear all tracked blocks."""
        self._blocks.clear()
        self._tag_index.clear()


def _generate_tag() -> int:
    """Generate a sequential tag (1 to 0xFFFF)."""
    _generate_tag._counter = getattr(_generate_tag, "_counter", 0) + 1
    if _generate_tag._counter > 0xFFFF:
        _generate_tag._counter = 1
    return _generate_tag._counter


def extract_tag(ptr: int) -> int:
    """Extract the tag from a tagged pointer."""
    return (ptr & TAG_MASK) >> 48


def extract_addr(ptr: int) -> int:
    """Extract the real address from a tagged pointer."""
    return ptr & ADDR_MASK


def encode_tag(addr: int, tag: int) -> int:
    """Encode a tag into a pointer's high bits."""
    return (addr & ADDR_MASK) | ((tag & 0xFFFF) << 48)


class TagBasedDetector:
    """Proactive memory safety detector using tagged pointers.

    For M5: recommended approach is to NOT modify pointer format (since
    Unicorn doesn't ignore high bits), but instead:
    1. Record allocation info and bounds in the state table
    2. Perform boundary checking via hook_mem_read/hook_mem_write
    3. Do tag checking only at malloc/free entry points
    """

    def __init__(self) -> None:
        self.state_table = MemoryStateTable()
        self._violations: list[dict] = []
        self._tag_counter = 0

    def next_tag(self) -> int:
        """Generate the next sequential tag."""
        self._tag_counter += 1
        if self._tag_counter > 0xFFFF:
            self._tag_counter = 1
        return self._tag_counter

    def check_access(self, ptr: int, access_size: int, access_type: str) -> dict | None:
        """Check a memory access for violations.

        Three checks in order:
        1. Tag mismatch (indicates UAF or pointer corruption)
        2. Freed block (UAF)
        3. Out-of-bounds (overflow)

        Returns violation dict or None if no violation.
        Note: tag=0 pointers are skipped (may be stack/global variables).
        """
        tag = extract_tag(ptr)
        if tag == 0:
            return None  # Skip untagged pointers

        real_addr = extract_addr(ptr)
        block = self.state_table.lookup(ptr)

        # If exact lookup fails but we have a tag, check for overflow
        # by finding a block with matching tag whose bounds are exceeded
        if block is None:
            if tag != 0:
                block = self.state_table.find_by_tag(tag)
            if block is None:
                return None

        real_addr = extract_addr(ptr)

        # Check 1: Tag mismatch
        if block.tag != tag:
            violation = {
                "type": "tag_mismatch",
                "ptr": hex(ptr),
                "real_addr": hex(real_addr),
                "expected_tag": block.tag,
                "actual_tag": tag,
                "access_type": access_type,
                "block_base": hex(block.base_addr),
                "block_size": block.size,
                "description": "Tag mismatch: pointer tag doesn't match allocation tag (UAF or corruption)",
            }
            self._violations.append(violation)
            return violation

        # Check 2: Freed block (UAF)
        if block.freed:
            violation = {
                "type": "uaf",
                "ptr": hex(ptr),
                "real_addr": hex(real_addr),
                "access_type": access_type,
                "block_base": hex(block.base_addr),
                "block_size": block.size,
                "description": "Use-after-free: accessing freed memory",
            }
            self._violations.append(violation)
            return violation

        # Check 3: Out-of-bounds
        access_end = real_addr + access_size
        block_end = block.base_addr + block.size
        if real_addr < block.base_addr or access_end > block_end:
            violation = {
                "type": "overflow",
                "ptr": hex(ptr),
                "real_addr": hex(real_addr),
                "access_type": access_type,
                "access_size": access_size,
                "block_base": hex(block.base_addr),
                "block_size": block.size,
                "description": "Buffer overflow: access beyond allocation bounds",
            }
            self._violations.append(violation)
            return violation

        return None

    def check_free(self, ptr: int, caller_addr: int = 0) -> dict | None:
        """Check a free() call for violations.

        Checks for: NULL (legal), unknown memory (invalid_free),
        already freed (double_free), tag mismatch.
        """
        if ptr == 0:
            return None  # free(NULL) is legal

        tag = extract_tag(ptr)
        block = self.state_table.lookup(ptr)

        if block is None:
            violation = {
                "type": "invalid_free",
                "ptr": hex(ptr),
                "description": "Freeing untracked memory",
            }
            self._violations.append(violation)
            return violation

        if block.freed:
            violation = {
                "type": "double_free",
                "ptr": hex(ptr),
                "block_base": hex(block.base_addr),
                "description": "Double free: freeing already-freed memory",
            }
            self._violations.append(violation)
            return violation

        if tag != 0 and block.tag != tag:
            violation = {
                "type": "tag_mismatch_free",
                "ptr": hex(ptr),
                "expected_tag": block.tag,
                "actual_tag": tag,
                "description": "Tag mismatch on free: pointer tag doesn't match allocation",
            }
            self._violations.append(violation)
            return violation

        # Mark as freed
        block.freed = True
        block.free_caller = caller_addr
        block.free_time = time.monotonic()
        return None

    def get_violations(self) -> list[dict]:
        """Return all detected violations."""
        return list(self._violations)

    def clear_violations(self) -> None:
        """Clear recorded violations."""
        self._violations.clear()

    def clear(self) -> None:
        """Clear all state."""
        self.state_table.clear()
        self._violations.clear()
        self._tag_counter = 0
