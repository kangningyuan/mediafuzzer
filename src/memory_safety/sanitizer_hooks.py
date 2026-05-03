"""Hooks for alloc/free/memory access functions for memory safety detection."""

import logging
import struct
from typing import Any

from src.memory_safety.tag_based import TagBasedDetector, MemoryStateTable
from src.emulation.hook_manager import HookManager

logger = logging.getLogger("mediafuzzer.memory_safety.sanitizer_hooks")

# Page-aligned allocation size for Qiling
ALLOC_PAGE_SIZE = 0x1000  # 4KB


class SanitizerHooks:
    """Install hooks for memory allocator/deallocator/access functions."""

    def __init__(
        self,
        ql: Any,
        detector: TagBasedDetector,
        hook_manager: HookManager,
    ) -> None:
        self.ql = ql
        self.detector = detector
        self.hook_manager = hook_manager

    def install(self) -> None:
        """Install all sanitizer hooks."""
        self._hook_allocators()
        self._hook_deallocators()
        self._hook_memory_access()
        logger.info("Memory safety sanitizer hooks installed")

    def _hook_allocators(self) -> None:
        """Hook malloc, calloc, realloc."""
        ql = self.ql
        detector = self.detector

        # malloc(size) -> tagged_ptr
        def _on_malloc(ql_ref: Any) -> None:
            size = ql_ref.arch.regs.x0
            # Page-align the allocation
            alloc_size = max(size, ALLOC_PAGE_SIZE)
            alloc_size = ((alloc_size + ALLOC_PAGE_SIZE - 1) // ALLOC_PAGE_SIZE) * ALLOC_PAGE_SIZE

            try:
                base_addr = ql_ref.mem.map_anywhere(alloc_size, info="malloc")
            except Exception as e:
                logger.warning("malloc: failed to map memory: %s", e)
                ql_ref.arch.regs.x0 = 0  # return NULL
                return

            tag = detector.next_tag()
            caller = ql_ref.arch.regs.x30  # LR = return address

            # Record allocation (without modifying pointer — per M5 recommendation)
            detector.state_table.add_block(base_addr, size or alloc_size, tag, caller_addr=caller)

            # Return base_addr (no tag encoding in pointer for M5 approach)
            ql_ref.arch.regs.x0 = base_addr

        # calloc(nmemb, size) -> tagged_ptr
        def _on_calloc(ql_ref: Any) -> None:
            nmemb = ql_ref.arch.regs.x0
            size = ql_ref.arch.regs.x1
            total = nmemb * size
            alloc_size = max(total, ALLOC_PAGE_SIZE)
            alloc_size = ((alloc_size + ALLOC_PAGE_SIZE - 1) // ALLOC_PAGE_SIZE) * ALLOC_PAGE_SIZE

            try:
                base_addr = ql_ref.mem.map_anywhere(alloc_size, info="calloc")
            except Exception as e:
                logger.warning("calloc: failed to map memory: %s", e)
                ql_ref.arch.regs.x0 = 0
                return

            # Zero-fill
            ql_ref.mem.write(base_addr, b"\x00" * alloc_size)

            tag = detector.next_tag()
            caller = ql_ref.arch.regs.x30
            detector.state_table.add_block(base_addr, total or alloc_size, tag, caller_addr=caller)

            ql_ref.arch.regs.x0 = base_addr

        # realloc(ptr, size) -> new_ptr
        def _on_realloc(ql_ref: Any) -> None:
            old_ptr = ql_ref.arch.regs.x0
            new_size = ql_ref.arch.regs.x1

            alloc_size = max(new_size, ALLOC_PAGE_SIZE)
            alloc_size = ((alloc_size + ALLOC_PAGE_SIZE - 1) // ALLOC_PAGE_SIZE) * ALLOC_PAGE_SIZE

            try:
                new_addr = ql_ref.mem.map_anywhere(alloc_size, info="realloc")
            except Exception as e:
                logger.warning("realloc: failed to map memory: %s", e)
                ql_ref.arch.regs.x0 = 0
                return

            # Copy old data if possible
            if old_ptr != 0:
                old_block = detector.state_table.lookup(old_ptr)
                if old_block:
                    copy_size = min(old_block.size, new_size)
                    try:
                        old_data = ql_ref.mem.read(old_ptr, copy_size)
                        ql_ref.mem.write(new_addr, bytes(old_data))
                    except Exception:
                        pass

                    # Mark old block as freed
                    old_block.freed = True
                    old_block.free_caller = ql_ref.arch.regs.x30
                    old_block.free_time = __import__("time").monotonic()

            tag = detector.next_tag()
            caller = ql_ref.arch.regs.x30
            detector.state_table.add_block(new_addr, new_size or alloc_size, tag, caller_addr=caller)

            ql_ref.arch.regs.x0 = new_addr

        alloc_hooks = {
            "malloc": _on_malloc,
            "calloc": _on_calloc,
            "realloc": _on_realloc,
        }
        for name, handler in alloc_hooks.items():
            if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
                try:
                    ql.os.set_api(name, handler)
                except Exception:
                    pass
            self.hook_manager.register_hook(name, handler, "memory_safety")

    def _hook_deallocators(self) -> None:
        """Hook free — check for NULL, unknown, double_free, tag_mismatch."""
        ql = self.ql
        detector = self.detector

        def _on_free(ql_ref: Any) -> None:
            ptr = ql_ref.arch.regs.x0
            caller = ql_ref.arch.regs.x30

            violation = detector.check_free(ptr, caller_addr=caller)
            if violation:
                logger.warning("Memory safety violation on free: %s", violation["type"])

            # Mark as freed in state table (even if violation found)
            if ptr != 0:
                block = detector.state_table.lookup(ptr)
                if block and not block.freed:
                    block.freed = True
                    block.free_caller = caller
                    block.free_time = __import__("time").monotonic()

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            try:
                ql.os.set_api("free", _on_free)
            except Exception:
                pass
        self.hook_manager.register_hook("free", _on_free, "memory_safety")

    def _hook_memory_access(self) -> None:
        """Hook memory read/write for UAF and overflow detection."""
        ql = self.ql
        detector = self.detector

        def _on_mem_read(ql_ref: Any, access_type: int, addr: int, size: int, value: int) -> None:
            violation = detector.check_access(addr, size, "read")
            if violation:
                logger.warning("Memory read violation: %s at %s", violation["type"], hex(addr))

        def _on_mem_write(ql_ref: Any, access_type: int, addr: int, size: int, value: int) -> None:
            violation = detector.check_access(addr, size, "write")
            if violation:
                logger.warning("Memory write violation: %s at %s", violation["type"], hex(addr))

        try:
            ql.hook_mem_read(_on_mem_read)
            ql.hook_mem_write(_on_mem_write)
        except Exception as e:
            logger.warning("Failed to install memory access hooks: %s", e)

        self.hook_manager.register_hook("mem_read", _on_mem_read, "memory_safety")
        self.hook_manager.register_hook("mem_write", _on_mem_write, "memory_safety")
