"""System call, file operation, and libc function simulation for Qiling."""

import logging
import os
import struct
from typing import Any, Callable

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
        self._hook_syscalls()
        self._hook_mem_invalid()
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

        # Pre-map a large heap region (64MB) to avoid per-allocation UC_ERR_MAP
        _heap_base = 0x80000000
        _heap_size = 64 * 1024 * 1024  # 64 MB
        try:
            ql.mem.map(_heap_base, _heap_size, info="fake_heap")
        except Exception:
            pass
        _heap_next: list[int] = [_heap_base]  # next allocation address

        def _on_malloc(ql_ref: Any) -> None:
            size = ql_ref.arch.regs.x0
            addr = _heap_next[0]
            _heap_next[0] += (size + 0xF) & ~0xF  # 16-byte aligned
            # Check heap bounds
            if _heap_next[0] > _heap_base + _heap_size:
                ql_ref.arch.regs.x0 = 0  # out of memory
                return
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
        """Patch PLT symbols using hook_address per entry.

        Scans the SO's .rela.plt and installs a hook_address callback for
        each PLT entry that doesn't have a real implementation. When the
        PLT stub is reached, the hook runs the registered Python handler
        (or a default "return 0" handler) and redirects PC to LR (x30)
        to simulate the function returning.

        Qiling pre-fills all GOT entries with the lazy resolver stub address,
        so we intercept ALL PLT entries (not just zero-GOT ones) and check
        at hook time whether the symbol has a real implementation.
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
                plt_offset = plt_sec.header.sh_addr
                plt_entry_size = 16  # standard aarch64 PLT entry size
                got_offsets = sorted(got_to_sym.keys())
                for idx, got_off in enumerate(got_offsets, start=1):
                    entry_addr = base + plt_offset + idx * plt_entry_size
                    sym_name = got_to_sym[got_off]
                    plt_addr[entry_addr] = sym_name

            if not plt_addr:
                return

            # Pre-collect specific handlers
            sym_handlers: dict[str, Any] = {}
            for addr, name in plt_addr.items():
                handler = self.hook_manager.get_hook(name)
                if handler is not None:
                    sym_handlers[name] = handler

            # Install hook_address for ALL PLT entries
            hooked_count = 0
            for addr, name in plt_addr.items():
                handler = sym_handlers.get(name)

                def _make_plt_hook(sym_name: str, sym_handler: Any | None) -> Callable:
                    def _on_plt(ql_ref: Any) -> None:
                        if sym_handler is not None:
                            sym_handler(ql_ref)
                        else:
                            # Default: return 0 for unhandled C++/system symbols
                            ql_ref.arch.regs.x0 = 0
                        # Redirect PC to return address (simulate function return)
                        ql_ref.arch.regs.pc = ql_ref.arch.regs.x30
                    return _on_plt

                ql.hook_address(_make_plt_hook(name, handler), addr)
                hooked_count += 1

            logger.debug("PLT hooks installed for %d/%d symbols (%d with handlers)",
                        hooked_count, len(plt_addr), len(sym_handlers))

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

    def _hook_syscalls(self) -> None:
        """Hook ARM64 SVC instructions (Linux syscalls).

        Many native functions issue syscalls directly (clock_gettime,
        gettid, futex, etc.) that Qiling's Linux emulation doesn't handle.
        Intercept unhandled interrupts and return success (0) by default.
        """
        ql = self.ql

        def _on_intr(ql_ref: Any, intno: int) -> None:
            # Return 0 (success) for any unhandled syscall/interrupt
            ql_ref.arch.regs.x0 = 0

        ql.hook_intr(_on_intr)

    def _hook_mem_invalid(self) -> None:
        """Hook invalid memory accesses to prevent UC_ERR_FETCH_UNMAPPED crashes.

        When execution jumps to an unmapped address (e.g., a vtable or function
        pointer that we couldn't resolve), redirect to the return address instead
        of crashing the entire emulation. For read/write to unmapped memory,
        auto-map the page so execution can continue.
        """
        ql = self.ql

        def _on_mem_invalid(ql_ref: Any, access: int, addr: int, size: int, value: int) -> bool:
            # UC_MEM_FETCH_UNMAPPED = 21 in unicorn-engine
            if access == 21:  # UC_MEM_FETCH_UNMAPPED
                # Redirect to return address with x0=0 (safe default)
                ql_ref.arch.regs.pc = ql_ref.arch.regs.x30
                ql_ref.arch.regs.x0 = 0
                return True
            # For read/write unmapped, try to map the page
            try:
                page_base = addr & ~0xFFF
                # Check if page is already mapped
                mapped = False
                for start, end, _, _ in ql_ref.mem.get_mapinfo():
                    if start <= page_base < end:
                        mapped = True
                        break
                if not mapped:
                    ql_ref.mem.map(page_base, 0x1000, info="auto_mapped")
            except Exception:
                pass
            return True  # Continue execution

        ql.hook_mem_invalid(_on_mem_invalid)
