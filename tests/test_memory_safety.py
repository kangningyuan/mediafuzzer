"""Tests for memory_safety module."""

import pytest

from src.memory_safety.tag_based import (
    TagBasedDetector,
    MemoryStateTable,
    extract_tag,
    extract_addr,
    encode_tag,
    MemBlock,
)


class TestTagEncoding:
    """Test tagged pointer encode/decode."""

    def test_encode_decode_roundtrip(self):
        """Encoding and decoding a tag preserves both tag and address."""
        addr = 0x0000_7FFF_1234_5678
        tag = 0x0042
        tagged = encode_tag(addr, tag)
        assert extract_tag(tagged) == tag
        assert extract_addr(tagged) == addr

    def test_extract_tag_zero(self):
        """Tag 0 extracts correctly."""
        ptr = 0x0000_0000_DEAD_BEEF
        assert extract_tag(ptr) == 0

    def test_extract_addr_no_tag(self):
        """Address without tag extracts correctly."""
        ptr = 0x0000_7FFF_1234_0000
        assert extract_addr(ptr) == 0x7FFF_1234_0000

    def test_encode_max_tag(self):
        """Maximum tag (0xFFFF) encodes correctly."""
        addr = 0x1000
        tag = 0xFFFF
        tagged = encode_tag(addr, tag)
        assert extract_tag(tagged) == tag


class TestMemoryStateTable:
    """Test memory state tracking."""

    def test_add_block_and_lookup(self):
        """Added block can be looked up."""
        table = MemoryStateTable()
        table.add_block(base_addr=0x1000, size=256, tag=1)
        block = table.lookup(0x1050)
        assert block is not None
        assert block.base_addr == 0x1000
        assert block.size == 256
        assert block.tag == 1
        assert block.freed is False

    def test_lookup_outside_block(self):
        """Lookup outside any block returns None."""
        table = MemoryStateTable()
        table.add_block(base_addr=0x1000, size=256, tag=1)
        assert table.lookup(0x2000) is None

    def test_free_marks_block(self):
        """Free marks block as freed."""
        table = MemoryStateTable()
        table.add_block(base_addr=0x1000, size=256, tag=1)
        block = table.free(0x1000)
        assert block is not None
        assert block.freed is True

    def test_clear(self):
        """Clear removes all blocks."""
        table = MemoryStateTable()
        table.add_block(base_addr=0x1000, size=256, tag=1)
        table.clear()
        assert table.lookup(0x1000) is None


class TestTagBasedDetector:
    """Test proactive memory safety detection."""

    def test_overflow_detection(self):
        """Out-of-bounds access is detected."""
        detector = TagBasedDetector()
        detector.state_table.add_block(base_addr=0x1000, size=16, tag=1)
        # Access beyond block boundary (with matching tag)
        tagged_ptr = encode_tag(0x1020, 1)  # 0x1020 is past the 16-byte block
        violation = detector.check_access(tagged_ptr, access_size=1, access_type="read")
        assert violation is not None
        assert violation["type"] == "overflow"

    def test_uaf_detection(self):
        """Use-after-free is detected."""
        detector = TagBasedDetector()
        block = detector.state_table.add_block(base_addr=0x1000, size=64, tag=1)
        block.freed = True  # Mark as freed
        tagged_ptr = encode_tag(0x1000, 1)
        violation = detector.check_access(tagged_ptr, access_size=4, access_type="read")
        assert violation is not None
        assert violation["type"] == "uaf"

    def test_double_free_detection(self):
        """Double free is detected."""
        detector = TagBasedDetector()
        detector.state_table.add_block(base_addr=0x1000, size=64, tag=1)
        # First free
        detector.check_free(0x1000)
        # Second free
        violation = detector.check_free(0x1000)
        assert violation is not None
        assert violation["type"] == "double_free"

    def test_valid_access_no_violation(self):
        """Valid access within bounds produces no violation."""
        detector = TagBasedDetector()
        detector.state_table.add_block(base_addr=0x1000, size=64, tag=1)
        # Access with tag=0 (untagged) — should be skipped
        violation = detector.check_access(0x1010, access_size=4, access_type="read")
        assert violation is None

    def test_free_null_is_legal(self):
        """free(NULL) produces no violation."""
        detector = TagBasedDetector()
        violation = detector.check_free(0)
        assert violation is None

    def test_get_violations(self):
        """get_violations returns all detected violations."""
        detector = TagBasedDetector()
        detector.state_table.add_block(base_addr=0x1000, size=64, tag=1)
        block = detector.state_table.add_block(base_addr=0x2000, size=64, tag=2)
        block.freed = True
        tagged_ptr = encode_tag(0x2000, 2)
        detector.check_access(tagged_ptr, access_size=4, access_type="read")
        detector.check_free(0x1000)
        detector.check_free(0x1000)
        violations = detector.get_violations()
        assert len(violations) >= 1
