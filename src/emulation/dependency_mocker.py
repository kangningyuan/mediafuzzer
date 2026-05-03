"""System call, file operation, and libc function simulation for Qiling."""

import logging
import os
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
        self._hook_file_io()
        self._hook_android_log()
        self._hook_pthread()
        self._hook_network()
        self._hook_misc()

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
