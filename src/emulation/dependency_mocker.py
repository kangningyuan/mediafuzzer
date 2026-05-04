"""System call, file operation, and libc function simulation for Qiling."""

import logging
import os
import struct
from typing import Any

from config.settings import settings
from config.file_formats import get_format
from src.emulation.hook_manager import HookManager

logger = logging.getLogger("mediafuzzer.emulation.dependency_mocker")


class DependencyMocker:
    """Simulates system calls, file I/O, Android log, pthread, and network."""

    def __init__(self, ql: Any, hook_manager: HookManager) -> None:
        self.ql = ql
        self.hook_manager = hook_manager
        self._fake_fd_counter = 1000
        self._fake_files: dict[int, bytes] = {}
        self._fake_file_pos: dict[int, int] = {}

    def setup_all(self) -> None:
        """Register all dependency hooks."""
        self._hook_libc_mem()
        self._hook_file_io()
        self._hook_android_log()
        self._hook_pthread()
        self._hook_network()
        self._hook_misc()
        self._patch_plt_got()

    def _next_fd(self) -> int:
        """Allocate a new fake file descriptor."""
        self._fake_fd_counter += 1
        return self._fake_fd_counter

    def _get_media_seed(self, filename: str) -> bytes:
        """Generate format-specific seed data based on file extension."""
        ext_map = {
            ".gif": "GIF", ".jpeg": "JPEG", ".jpg": "JPEG",
            ".png": "PNG", ".webp": "WebP", ".mp4": "MP4",
        }
        _, ext = os.path.splitext(filename.lower())
        format_name = ext_map.get(ext)
        if format_name:
            try:
                skeleton = get_format(format_name)
                return skeleton.generate_seed()
            except KeyError:
                pass
        return os.urandom(64)

    def _hook_file_io(self) -> None:
        """Hook fopen, fread, fwrite, fclose, fseek, ftell."""
        ql = self.ql

        # fopen — returns fake FILE* with media seed data for multimedia files
        def _on_fopen(ql_ref: Any) -> None:
            try:
                # Read filename from x0 (first arg)
                filename_addr = ql_ref.arch.regs.x0
                filename = ql_ref.mem.string(filename_addr)
                logger.debug("fopen(%s)", filename)
            except Exception:
                filename = ""

            fd = self._next_fd()
            seed_data = self._get_media_seed(filename)
            self._fake_files[fd] = seed_data
            self._fake_file_pos[fd] = 0
            # Return fd as FILE*
            ql_ref.arch.regs.x0 = fd

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            ql.os.set_api("fopen", _on_fopen)
            ql.os.set_api("fopen64", _on_fopen)

        self.hook_manager.register_hook("fopen", _on_fopen, "dependency")

        # fread — reads from fake file store
        def _on_fread(ql_ref: Any) -> None:
            buf_addr = ql_ref.arch.regs.x0
            size = ql_ref.arch.regs.x1
            count = ql_ref.arch.regs.x2
            # fd = x3 (FILE*)
            fd = ql_ref.arch.regs.x3

            if fd in self._fake_files:
                data = self._fake_files[fd]
                pos = self._fake_file_pos.get(fd, 0)
                remaining = len(data) - pos
                read_size = min(size * count, remaining)
                if read_size > 0:
                    ql_ref.mem.write(buf_addr, data[pos:pos + read_size])
                    self._fake_file_pos[fd] = pos + read_size
                ql_ref.arch.regs.x0 = read_size // max(size, 1)
            else:
                ql_ref.arch.regs.x0 = 0

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            ql.os.set_api("fread", _on_fread)
        self.hook_manager.register_hook("fread", _on_fread, "dependency")

        # fwrite — discards data
        def _on_fwrite(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = ql_ref.arch.regs.x2  # return count

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            ql.os.set_api("fwrite", _on_fwrite)
        self.hook_manager.register_hook("fwrite", _on_fwrite, "dependency")

        # fclose — removes from fake file store
        def _on_fclose(ql_ref: Any) -> None:
            fd = ql_ref.arch.regs.x0
            self._fake_files.pop(fd, None)
            self._fake_file_pos.pop(fd, None)
            ql_ref.arch.regs.x0 = 0  # success

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            ql.os.set_api("fclose", _on_fclose)
        self.hook_manager.register_hook("fclose", _on_fclose, "dependency")

        # fseek
        def _on_fseek(ql_ref: Any) -> None:
            fd = ql_ref.arch.regs.x0
            offset = ql_ref.arch.regs.x1
            if fd in self._fake_files:
                self._fake_file_pos[fd] = offset
            ql_ref.arch.regs.x0 = 0  # success

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            ql.os.set_api("fseek", _on_fseek)
            ql.os.set_api("fseeko", _on_fseek)
        self.hook_manager.register_hook("fseek", _on_fseek, "dependency")

        # ftell
        def _on_ftell(ql_ref: Any) -> None:
            fd = ql_ref.arch.regs.x0
            ql_ref.arch.regs.x0 = self._fake_file_pos.get(fd, 0)

        if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
            ql.os.set_api("ftell", _on_ftell)
        self.hook_manager.register_hook("ftell", _on_ftell, "dependency")

    def _hook_android_log(self) -> None:
        """Hook Android log functions — no-op."""
        ql = self.ql

        def _on_log(ql_ref: Any) -> None:
            pass  # Discard log output

        log_funcs = ["__android_log_print", "__android_log_write",
                     "__android_log_vprint", "__android_log_buf_write"]
        for func in log_funcs:
            if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
                try:
                    ql.os.set_api(func, _on_log)
                except Exception:
                    pass
        self.hook_manager.register_hook("android_log", _on_log, "dependency")

    def _hook_pthread(self) -> None:
        """Hook pthread functions — return success without creating threads."""
        ql = self.ql

        def _on_pthread_create(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0  # success

        def _on_pthread_join(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0  # success

        def _on_pthread_mutex_init(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0

        def _on_pthread_mutex_lock(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0

        def _on_pthread_mutex_unlock(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0

        pthread_funcs = {
            "pthread_create": _on_pthread_create,
            "pthread_join": _on_pthread_join,
            "pthread_mutex_init": _on_pthread_mutex_init,
            "pthread_mutex_lock": _on_pthread_mutex_lock,
            "pthread_mutex_unlock": _on_pthread_mutex_unlock,
        }
        for name, handler in pthread_funcs.items():
            if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
                try:
                    ql.os.set_api(name, handler)
                except Exception:
                    pass
            self.hook_manager.register_hook(name, handler, "dependency")

    def _hook_network(self) -> None:
        """Hook network functions — socket/connect return -1."""
        ql = self.ql

        def _on_socket(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0xFFFFFFFFFFFFFFFF  # -1

        def _on_connect(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0xFFFFFFFFFFFFFFFF  # -1

        net_funcs = {"socket": _on_socket, "connect": _on_connect}
        for name, handler in net_funcs.items():
            if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
                try:
                    ql.os.set_api(name, handler)
                except Exception:
                    pass
            self.hook_manager.register_hook(name, handler, "dependency")

    def _hook_libc_mem(self) -> None:
        """Hook malloc/free/memcpy/memset so unlinked SOs can run."""
        ql = self.ql
        _heap_next: list[int] = [0x80000000]  # heap base for fake allocations

        def _on_malloc(ql_ref: Any) -> None:
            size = ql_ref.arch.regs.x0
            addr = _heap_next[0]
            _heap_next[0] += (size + 0xF) & ~0xF  # 16-byte aligned
            # Map the memory region
            try:
                ql_ref.mem.map(addr, (size + 0xFFF) & ~0xFFF, info="fake_malloc")
            except Exception:
                pass
            ql_ref.arch.regs.x0 = addr

        def _on_free(ql_ref: Any) -> None:
            pass  # no-op

        def _on_memcpy(ql_ref: Any) -> None:
            dst = ql_ref.arch.regs.x0
            src = ql_ref.arch.regs.x1
            n = ql_ref.arch.regs.x2
            try:
                data = ql_ref.mem.read(src, n)
                ql_ref.mem.write(dst, bytes(data))
            except Exception:
                pass
            # x0 already holds dst (return value per memcpy spec)

        def _on_memset(ql_ref: Any) -> None:
            dst = ql_ref.arch.regs.x0
            val = ql_ref.arch.regs.x1 & 0xFF
            n = ql_ref.arch.regs.x2
            try:
                ql_ref.mem.write(dst, bytes([val]) * n)
            except Exception:
                pass

        mem_funcs = {
            "malloc": _on_malloc, "calloc": _on_malloc,
            "free": _on_free,
            "memcpy": _on_memcpy, "memmove": _on_memcpy,
            "memset": _on_memset,
        }
        for name, handler in mem_funcs.items():
            if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
                try:
                    ql.os.set_api(name, handler)
                except Exception:
                    pass
            self.hook_manager.register_hook(name, handler, "dependency")

    def _patch_plt_got(self) -> None:
        """Patch unresolved PLT symbols using a hook_code interceptor.

        Scans the SO's .rela.plt for GOT entries that are zero (unresolved).
        Collects the PLT entry addresses for each symbol and installs a single
        hook_code callback that intercepts calls to those PLT entries, runs
        the registered Python handler, and redirects PC to the caller's return
        address (LR/x30) to simulate the function returning.
        """
        ql = self.ql
        try:
            from elftools.elf.elffile import ELFFile

            so_path = ""
            if ql.loader.images:
                so_path = ql.loader.images[0].path
            if not so_path:
                return

            base = ql.loader.images[0].base
            plt_addr: dict[int, str] = {}  # runtime PLT addr -> symbol name

            with open(so_path, "rb") as f:
                elf = ELFFile(f)
                rela_plt = elf.get_section_by_name(".rela.plt")
                if rela_plt is None:
                    return
                symtab = elf.get_section_by_name(".dynsym")
                if symtab is None:
                    return
                plt_sec = elf.get_section_by_name(".plt")
                if plt_sec is None:
                    return

                # Build mapping: GOT offset -> symbol name
                got_to_sym: dict[int, str] = {}
                for rel in rela_plt.iter_relocations():
                    sym = symtab.get_symbol(rel.entry.r_info_sym)
                    got_to_sym[rel.entry.r_offset] = sym.name

                # Map PLT entries to symbols by matching GOT offsets
                # PLT layout on aarch64: entry 0 is resolver, entries 1..N are stubs
                # Each stub loads from its GOT slot and branches.
                # We reverse-match by scanning PLT code for ADRP+LDR pairs.
                # Simpler: just map PLT entry index to the relocation order.
                plt_offset = plt_sec.header.sh_addr
                plt_entry_size = 16  # standard aarch64 PLT entry size
                got_offsets = sorted(got_to_sym.keys())
                for idx, got_off in enumerate(got_offsets, start=1):
                    entry_addr = base + plt_offset + idx * plt_entry_size
                    sym_name = got_to_sym[got_off]
                    plt_addr[entry_addr] = sym_name

            if not plt_addr:
                return

            # Build reverse map: symbol name -> handler
            sym_handlers: dict[str, Any] = {}
            for addr, name in plt_addr.items():
                handler = self.hook_manager.get_hook(name)
                if handler is not None:
                    sym_handlers[name] = handler
                else:
                    logger.debug("No handler for unresolved PLT symbol: %s", name)

            if not sym_handlers:
                return

            # Filter to only PLT entries that have handlers and are unresolved
            target_addrs = set()
            for addr, name in plt_addr.items():
                if name in sym_handlers:
                    # Check if GOT entry is zero
                    got_off = [k for k, v in got_to_sym.items() if v == name][0]
                    got_addr = base + got_off
                    got_val = int.from_bytes(ql.mem.read(got_addr, 8), "little")
                    if got_val == 0:
                        target_addrs.add(addr)
                        logger.debug("Will intercept PLT: %s at 0x%x", name, addr)

            if not target_addrs:
                return

            # Install hook_code interceptor
            def _plt_interceptor(ql_ref: Any, addr: int, size: int) -> None:
                if addr not in target_addrs:
                    return
                name = plt_addr[addr]
                handler = sym_handlers.get(name)
                if handler is not None:
                    handler(ql_ref)
                    # Redirect PC to return address (simulate function return)
                    ql_ref.arch.regs.pc = ql_ref.arch.regs.x30

            ql.hook_code(_plt_interceptor)
            logger.debug("PLT interceptor installed for %d symbols", len(target_addrs))

        except Exception as e:
            logger.debug("PLT GOT patching failed (non-fatal): %s", e)

    def _hook_misc(self) -> None:
        """Hook miscellaneous: getenv, dlopen, dlsym."""
        ql = self.ql

        def _on_getenv(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0  # NULL

        def _on_dlopen(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 1  # non-NULL handle

        def _on_dlsym(ql_ref: Any) -> None:
            ql_ref.arch.regs.x0 = 0  # NULL (symbol not found)

        misc_funcs = {"getenv": _on_getenv, "dlopen": _on_dlopen, "dlsym": _on_dlsym}
        for name, handler in misc_funcs.items():
            if hasattr(ql, 'os') and hasattr(ql.os, 'set_api'):
                try:
                    ql.os.set_api(name, handler)
                except Exception:
                    pass
            self.hook_manager.register_hook(name, handler, "dependency")
