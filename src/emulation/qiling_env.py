"""Qiling environment initialization, JNI stubs, and emulated function execution."""

import logging
import struct
from typing import Any, Callable

from config.settings import settings
from src.emulation.hook_manager import HookManager
from src.emulation.dependency_mocker import DependencyMocker

logger = logging.getLogger("mediafuzzer.emulation.qiling_env")


class JNIPorter:
    """Constructs a fake JNI environment table in emulated memory.

    Layout: JNIEnv** -> JNIEnv* -> JNINativeInterface_* vtable
    The vtable has 232 function pointer slots (ARM64, 8 bytes each = 1856 bytes).
    """

    VTABLE_SLOTS = 232
    VTABLE_SIZE = VTABLE_SLOTS * 8  # 1856 bytes

    def __init__(self, ql: Any) -> None:
        self.ql = ql
        self._vtable_addr: int = 0
        self._env_addr: int = 0
        self._env_ptr_addr: int = 0
        self._stub_hooks: list[tuple[int, Callable]] = []

    def setup(self) -> int:
        """Allocate and initialize JNI environment. Returns JNIEnv** address."""
        ql = self.ql

        # Allocate vtable (232 slots x 8 bytes)
        self._vtable_addr = ql.mem.map_anywhere(self.VTABLE_SIZE, info="JNI vtable")

        # Allocate JNIEnv* (8 bytes — pointer to vtable)
        self._env_addr = ql.mem.map_anywhere(8, info="JNIEnv")

        # Allocate JNIEnv** (8 bytes — pointer to JNIEnv*)
        self._env_ptr_addr = ql.mem.map_anywhere(8, info="JNIEnv**")

        # Write vtable pointer into JNIEnv*
        ql.mem.write(self._env_addr, struct.pack("<Q", self._vtable_addr))

        # Write JNIEnv* into JNIEnv**
        ql.mem.write(self._env_ptr_addr, struct.pack("<Q", self._env_addr))

        # Set up JNI stub functions in vtable
        self._setup_jni_stubs()

        logger.debug(
            "JNI environment: vtable=0x%x, env=0x%x, env_ptr=0x%x",
            self._vtable_addr, self._env_addr, self._env_ptr_addr,
        )
        return self._env_ptr_addr

    def _setup_jni_stubs(self) -> None:
        """Register JNI function stubs in the vtable."""
        ql = self.ql

        # JNI function index -> (name, return_value)
        # See jni.h for the full JNINativeInterface_ table
        jni_functions = {
            4: ("GetVersion", 0x00010006),      # JNI 1.6
            6: ("FindClass", 0x1),              # non-NULL jclass
            27: ("NewStringUTF", 0x2),          # non-NULL jstring
            28: ("GetStringUTFLength", 0),      # length 0
            29: ("GetStringUTFChars", 0x3),     # non-NULL
            30: ("ReleaseStringUTFChars", 0),   # void
            36: ("GetArrayLength", 0),          # length 0
            37: ("NewObjectArray", 0x4),        # non-NULL
            41: ("GetObjectArrayElement", 0x5), # non-NULL
            171: ("GetByteArrayElements", 0x6), # non-NULL
            184: ("ReleaseByteArrayElements", 0),  # void
            200: ("GetByteArrayRegion", 0),     # void
            207: ("NewByteArray", 0x7),         # non-NULL
        }

        for idx, (name, ret_val) in jni_functions.items():
            stub_addr = self._asm_stub_return(ret_val)
            # Write stub address into vtable slot
            offset = idx * 8
            ql.mem.write(self._vtable_addr + offset, struct.pack("<Q", stub_addr))

            # Register address hook for the stub
            def _make_handler(func_name: str) -> Callable:
                def handler(ql_ref: Any) -> None:
                    logger.debug("JNI stub called: %s", func_name)
                return handler

            ql.hook_address(_make_handler(name), stub_addr)
            self._stub_hooks.append((stub_addr, _make_handler(name)))

    def _asm_stub_return(self, value: int) -> int:
        """Generate ARM64 machine code stub that returns a fixed value.

        MOV X0, #value; RET
        Handles 16-bit, 32-bit, and 64-bit values using MOVZ/MOVK instructions.
        """
        ql = self.ql
        code = bytearray()

        if value <= 0xFFFF:
            # MOVZ X0, #imm16
            code += struct.pack("<I", 0xD2800000 | (value << 5))
        elif value <= 0xFFFFFFFF:
            # MOVZ X0, #imm16 (lower)
            code += struct.pack("<I", 0xD2800000 | ((value & 0xFFFF) << 5))
            # MOVK X0, #imm16, LSL #16 (upper)
            code += struct.pack("<I", 0xF2A00000 | (((value >> 16) & 0xFFFF) << 5))
        else:
            # MOVZ X0, #imm16 (bits 0-15)
            code += struct.pack("<I", 0xD2800000 | ((value & 0xFFFF) << 5))
            # MOVK X0, #imm16, LSL #16 (bits 16-31)
            code += struct.pack("<I", 0xF2A00000 | (((value >> 16) & 0xFFFF) << 5))
            # MOVK X0, #imm16, LSL #32 (bits 32-47)
            code += struct.pack("<I", 0xF2C00000 | (((value >> 32) & 0xFFFF) << 5))
            # MOVK X0, #imm16, LSL #48 (bits 48-63)
            code += struct.pack("<I", 0xF2E00000 | (((value >> 48) & 0xFFFF) << 5))

        # RET
        code += struct.pack("<I", 0xD65F03C0)

        # Map code into memory
        addr = ql.mem.map_anywhere(len(code), info=f"stub_0x{value:x}")
        ql.mem.write(addr, bytes(code))
        return addr

    @property
    def env_ptr_addr(self) -> int:
        return self._env_ptr_addr


class QilingEnv:
    """Wrapper around Qiling instance configuration."""

    def __init__(
        self,
        rootfs: str | None = None,
        arch: str | None = None,
        os_name: str | None = None,
        verbose: int | None = None,
    ) -> None:
        self.rootfs = rootfs or settings.QL_ROOTFS_PATH
        self.arch = arch or settings.QL_ARCH
        self.os_name = os_name or settings.QL_OS
        self.verbose = verbose if verbose is not None else settings.QL_VERBOSE


class EmulatedJNIFunc:
    """Provides a runnable virtual execution environment for a single native function.

    Handles SO loading, function calling, JNI stubs, and timeout management.
    """

    def __init__(
        self,
        so_path: str,
        func_symbol: str,
        rootfs: str | None = None,
        arch: str | None = None,
    ) -> None:
        if not so_path:
            raise FileNotFoundError("SO path is empty")

        self.so_path = so_path
        self.func_symbol = func_symbol
        self.env = QilingEnv(rootfs=rootfs, arch=arch)

        self.ql: Any = None
        self.jni_porter: JNIPorter | None = None
        self.hook_manager = HookManager()
        self.dependency_mocker: DependencyMocker | None = None
        self._func_addr: int = 0
        self._return_addr: int = 0
        self._input_addr: int = 0
        self._initialized = False

    def initialize(self) -> None:
        """Create Qiling instance, register JNI stubs and hooks, resolve function."""
        from qiling import Qiling  # type: ignore[import-untyped]
        from qiling.const import QL_ARCH, QL_OS  # type: ignore[import-untyped]

        arch_map = {
            "arm64": QL_ARCH.ARM64,
            "arm": QL_ARCH.ARM,
            "x86": QL_ARCH.X86,
            "x8664": QL_ARCH.X8664,
        }
        os_map = {
            "linux": QL_OS.LINUX,
            "android": QL_OS.LINUX,  # Qiling uses LINUX for Android rootfs
        }

        ql_arch = arch_map.get(self.env.arch)
        ql_os = os_map.get(self.env.os_name)
        if ql_arch is None:
            raise RuntimeError(f"Unsupported architecture: {self.env.arch}")
        if ql_os is None:
            raise RuntimeError(f"Unsupported OS: {self.env.os_name}")

        if not self.env.rootfs:
            raise RuntimeError("Qiling rootfs path is not configured")

        # Create Qiling instance
        self.ql = Qiling(
            [self.so_path],
            self.env.rootfs,
            archtype=ql_arch,
            ostype=ql_os,
            verbose=self.env.verbose,
        )

        # Set up JNI environment
        self.jni_porter = JNIPorter(self.ql)
        self.jni_porter.setup()

        # Set up dependency mocker (file I/O, Android log, etc.)
        self.dependency_mocker = DependencyMocker(self.ql, self.hook_manager)
        self.dependency_mocker.setup_all()

        # Resolve function address
        self._resolve_function_address()

        # Execute SO init (.init_array, JNI_OnLoad)
        self._run_init()

        self._initialized = True
        logger.info(
            "EmulatedJNIFunc initialized: %s @ 0x%x",
            self.func_symbol, self._func_addr,
        )

    def _resolve_function_address(self) -> None:
        """Resolve function address from Qiling loader symbols or ELF parsing."""
        # Try Qiling loader APIs first (works on some Qiling versions)
        try:
            symbols = self.ql.loader.symbols
            for sym in symbols:
                if hasattr(sym, 'name') and sym.name == self.func_symbol:
                    self._func_addr = sym.addr
                    break
        except Exception:
            pass

        if not self._func_addr:
            try:
                for name, addr in self.ql.loader.export_symbols.items():
                    if name == self.func_symbol:
                        self._func_addr = addr
                        break
            except Exception:
                pass

        # Fallback: parse ELF with pyelftools, compute runtime address from base
        if not self._func_addr:
            self._func_addr = self._resolve_via_elf()

        if not self._func_addr:
            raise RuntimeError(
                f"Symbol '{self.func_symbol}' not found in {self.so_path}"
            )

    def _resolve_via_elf(self) -> int:
        """Resolve symbol by parsing ELF file and adding Qiling loader base."""
        try:
            from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

            with open(self.so_path, "rb") as f:
                elf = ELFFile(f)
                sym_tab = elf.get_section_by_name(".dynsym")
                if sym_tab is None:
                    return 0
                for sym in sym_tab.iter_symbols():
                    if sym.name == self.func_symbol and sym.entry.st_shndx != "SHN_UNDEF":
                        # Get the load base from Qiling's first image
                        base = 0
                        if self.ql.loader.images:
                            base = self.ql.loader.images[0].base
                        return base + sym.entry.st_value
        except Exception as e:
            logger.debug("ELF resolution failed: %s", e)
        return 0

    def _run_init(self) -> None:
        """Execute SO initialization (.init_array functions, JNI_OnLoad)."""
        try:
            # Qiling should handle .init_array automatically
            # Try to call JNI_OnLoad if present
            jni_onload = 0
            try:
                for sym in self.ql.loader.symbols:
                    if hasattr(sym, 'name') and sym.name == "JNI_OnLoad":
                        jni_onload = sym.addr
                        break
            except Exception:
                pass

            # Fallback: resolve JNI_OnLoad via ELF
            if not jni_onload:
                saved = self.func_symbol
                self.func_symbol = "JNI_OnLoad"
                jni_onload = self._resolve_via_elf()
                self.func_symbol = saved

            if jni_onload:
                logger.debug("Calling JNI_OnLoad at 0x%x", jni_onload)
                # Set up args: JNI_OnLoad(JavaVM* vm, void* reserved)
                # For now, pass NULL for both
                self.ql.arch.regs.x0 = 0
                self.ql.arch.regs.x1 = 0
                self.ql.run(begin=jni_onload, end=jni_onload + 4)
        except Exception as e:
            logger.warning("SO init failed (non-fatal): %s", e)

    def call_function(self, input_data: bytes, timeout_ms: int | None = None) -> int:
        """Execute the target function with input_data.

        Sets ARM64 registers:
          x0 = JNIEnv** (from JNIPorter)
          x1 = jobject / NULL
          x2 = data address
          x3 = data length
        Returns the value of x0 after execution.
        """
        if not self._initialized or self.ql is None:
            raise RuntimeError("EmulatedJNIFunc not initialized")

        ql = self.ql
        timeout = timeout_ms or settings.QL_TIMEOUT

        # Map input data into emulated memory
        input_size = max(len(input_data), 1)
        self._input_addr = ql.mem.map_anywhere(input_size, info="fuzz_input")
        ql.mem.write(self._input_addr, input_data)

        # Set up a return address hook
        self._return_addr = ql.mem.map_anywhere(4, info="return_addr")
        # Write RET instruction at return address
        ret_code = struct.pack("<I", 0xD65F03C0)  # ARM64 RET
        ql.mem.write(self._return_addr, ret_code)

        # Set ARM64 registers per calling convention
        ql.arch.regs.x0 = self.jni_porter.env_ptr_addr if self.jni_porter else 0
        ql.arch.regs.x1 = 0  # jobject = NULL
        ql.arch.regs.x2 = self._input_addr
        ql.arch.regs.x3 = len(input_data)
        ql.arch.regs.x29 = 0  # Frame pointer
        ql.arch.regs.x30 = self._return_addr  # Link register -> return

        # Set up return address hook
        returned = [False]
        exception_occurred = [None]

        def _on_return(ql_ref: Any) -> None:
            returned[0] = True

        ql.hook_address(_on_return, self._return_addr)

        try:
            ql.run(
                begin=self._func_addr,
                end=self._return_addr,
                timeout=timeout,
            )
        except Exception as e:
            exception_occurred[0] = e
            logger.warning("Execution exception: %s", e)

        # Read return value
        ret_val = -1
        if returned[0]:
            try:
                ret_val = ql.arch.regs.x0
            except Exception:
                pass
        elif exception_occurred[0]:
            logger.warning("Function did not return normally: %s", exception_occurred[0])
            ret_val = -1
        else:
            logger.warning("Function execution timed out after %dms", timeout)
            ret_val = -1

        # Clean up mapped memory
        try:
            ql.mem.unmap(self._input_addr, input_size)
            ql.mem.unmap(self._return_addr, 4)
        except Exception:
            pass

        return ret_val

    def destroy(self) -> None:
        """Clear all hooks and null Qiling instance."""
        if self.ql is not None:
            self.hook_manager.clear_all()
            self.ql = None
            self._initialized = False
            logger.debug("EmulatedJNIFunc destroyed")
