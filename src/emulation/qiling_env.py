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
        """Register JNI function stubs in the vtable.

        All 232 slots must be populated to prevent branch-to-zero crashes.
        Slots without a specific return value get a default safe stub.
        See jni.h JNINativeInterface_ for the full table.
        """
        ql = self.ql

        # JNI function index -> (name, return_value)
        # Specific return values for commonly-called functions
        jni_functions = {
            4: ("GetVersion", 0x00010006),          # JNI 1.6
            6: ("FindClass", 0x1),                  # non-NULL jclass
            7: ("FromReflectedMethod", 0),           # NULL jmethodID
            8: ("FromReflectedField", 0),            # NULL jfieldID
            9: ("ToReflectedMethod", 0),             # NULL jobject
            10: ("GetSuperclass", 0x1),              # non-NULL jclass
            11: ("IsAssignableFrom", 0),             # JNI_FALSE
            12: ("ToReflectedField", 0),             # NULL jobject
            13: ("Throw", 0),                       # 0 = success
            14: ("ThrowNew", 0),                    # 0 = success
            15: ("ExceptionOccurred", 0),            # NULL jthrowable
            16: ("ExceptionDescribe", 0),            # void
            17: ("ExceptionClear", 0),               # void
            18: ("FatalError", 0),                  # void (noreturn in real JNI)
            19: ("PushLocalFrame", 0),               # 0 = success
            20: ("PopLocalFrame", 0),                # NULL jobject
            21: ("NewGlobalRef", 0x1),              # non-NULL
            22: ("DeleteGlobalRef", 0),              # void
            23: ("DeleteLocalRef", 0),               # void
            24: ("IsSameObject", 0),                # JNI_FALSE
            25: ("NewLocalRef", 0x1),               # non-NULL
            26: ("EnsureLocalCapacity", 0),          # 0 = success
            27: ("NewStringUTF", 0x2),              # non-NULL jstring
            28: ("GetStringUTFLength", 0),          # length 0
            29: ("GetStringUTFChars", 0x3),         # non-NULL
            30: ("ReleaseStringUTFChars", 0),       # void
            31: ("NewString", 0x2),                 # non-NULL jstring
            32: ("GetStringLength", 0),              # length 0
            33: ("GetStringChars", 0x3),            # non-NULL
            34: ("ReleaseStringChars", 0),          # void
            35: ("NewStringRegion", 0),              # void
            36: ("GetArrayLength", 0),              # length 0
            37: ("NewObjectArray", 0x4),            # non-NULL
            38: ("GetObjectArrayElement", 0x5),     # non-NULL
            39: ("SetObjectArrayElement", 0),       # void
            40: ("NewBooleanArray", 0x1),           # non-NULL
            41: ("NewByteArray", 0x7),              # non-NULL
            42: ("NewCharArray", 0x1),              # non-NULL
            43: ("NewShortArray", 0x1),             # non-NULL
            44: ("NewIntArray", 0x1),               # non-NULL
            45: ("NewLongArray", 0x1),              # non-NULL
            46: ("NewFloatArray", 0x1),             # non-NULL
            47: ("NewDoubleArray", 0x1),            # non-NULL
            48: ("GetBooleanArrayElements", 0x6),   # non-NULL
            49: ("GetByteArrayElements", 0x6),      # non-NULL
            50: ("GetCharArrayElements", 0x6),      # non-NULL
            51: ("GetShortArrayElements", 0x6),     # non-NULL
            52: ("GetIntArrayElements", 0x6),       # non-NULL
            53: ("GetLongArrayElements", 0x6),      # non-NULL
            54: ("GetFloatArrayElements", 0x6),     # non-NULL
            55: ("GetDoubleArrayElements", 0x6),    # non-NULL
            56: ("ReleaseBooleanArrayElements", 0),  # void
            57: ("ReleaseByteArrayElements", 0),     # void
            58: ("ReleaseCharArrayElements", 0),     # void
            59: ("ReleaseShortArrayElements", 0),    # void
            60: ("ReleaseIntArrayElements", 0),      # void
            61: ("ReleaseLongArrayElements", 0),     # void
            62: ("ReleaseFloatArrayElements", 0),    # void
            63: ("ReleaseDoubleArrayElements", 0),   # void
            64: ("GetBooleanArrayRegion", 0),        # void
            65: ("GetByteArrayRegion", 0),           # void
            66: ("GetCharArrayRegion", 0),           # void
            67: ("GetShortArrayRegion", 0),          # void
            68: ("GetIntArrayRegion", 0),            # void
            69: ("GetLongArrayRegion", 0),           # void
            70: ("GetFloatArrayRegion", 0),          # void
            71: ("GetDoubleArrayRegion", 0),         # void
            72: ("SetBooleanArrayRegion", 0),        # void
            73: ("SetByteArrayRegion", 0),           # void
            74: ("SetCharArrayRegion", 0),           # void
            75: ("SetShortArrayRegion", 0),          # void
            76: ("SetIntArrayRegion", 0),            # void
            77: ("SetLongArrayRegion", 0),           # void
            78: ("SetFloatArrayRegion", 0),          # void
            79: ("SetDoubleArrayRegion", 0),         # void
            80: ("RegisterNatives", 0),              # 0 = success
            81: ("UnregisterNatives", 0),            # 0 = success
            82: ("MonitorEnter", 0),                 # 0 = success
            83: ("MonitorExit", 0),                  # 0 = success
            84: ("GetJavaVM", 0x1),                 # non-NULL
            85: ("GetStringRegion", 0),              # void
            86: ("GetStringUTFRegion", 0),           # void
            87: ("GetPrimitiveArrayCritical", 0x6),  # non-NULL
            88: ("ReleasePrimitiveArrayCritical", 0), # void
            89: ("GetStringCritical", 0x3),          # non-NULL
            90: ("ReleaseStringCritical", 0),        # void
            91: ("NewWeakGlobalRef", 0x1),          # non-NULL
            92: ("DeleteWeakGlobalRef", 0),          # void
            93: ("ExceptionCheck", 0),              # JNI_FALSE
            94: ("NewDirectByteBuffer", 0x1),       # non-NULL
            95: ("GetDirectBufferAddress", 0x1),    # non-NULL
            96: ("GetDirectBufferCapacity", 0),     # 0
            97: ("GetObjectClass", 0x1),            # non-NULL jclass
            98: ("IsInstanceOf", 0),                # JNI_FALSE
            99: ("GetMethodID", 0x1),              # non-NULL jmethodID
            100: ("GetObjectField", 0),             # NULL jobject
            101: ("GetBooleanField", 0),            # JNI_FALSE
            102: ("GetByteField", 0),               # 0
            103: ("GetCharField", 0),               # 0
            104: ("GetShortField", 0),              # 0
            105: ("GetIntField", 0),                # 0
            106: ("GetLongField", 0),               # 0
            107: ("GetFloatField", 0),              # 0.0
            108: ("GetDoubleField", 0),             # 0.0
            109: ("SetObjectField", 0),             # void
            110: ("SetBooleanField", 0),            # void
            111: ("SetByteField", 0),               # void
            112: ("SetCharField", 0),               # void
            113: ("SetShortField", 0),              # void
            114: ("SetIntField", 0),                # void
            115: ("SetLongField", 0),               # void
            116: ("SetFloatField", 0),              # void
            117: ("SetDoubleField", 0),             # void
            118: ("GetStaticMethodID", 0x1),       # non-NULL
            119: ("CallStaticObjectMethod", 0),     # NULL
            120: ("CallStaticObjectMethodV", 0),    # NULL
            121: ("CallStaticObjectMethodA", 0),    # NULL
            122: ("CallStaticBooleanMethod", 0),    # JNI_FALSE
            123: ("CallStaticBooleanMethodV", 0),   # JNI_FALSE
            124: ("CallStaticBooleanMethodA", 0),   # JNI_FALSE
            125: ("CallStaticByteMethod", 0),       # 0
            126: ("CallStaticByteMethodV", 0),      # 0
            127: ("CallStaticByteMethodA", 0),      # 0
            128: ("CallStaticCharMethod", 0),       # 0
            129: ("CallStaticCharMethodV", 0),      # 0
            130: ("CallStaticCharMethodA", 0),      # 0
            131: ("CallStaticShortMethod", 0),      # 0
            132: ("CallStaticShortMethodV", 0),     # 0
            133: ("CallStaticShortMethodA", 0),     # 0
            134: ("CallStaticIntMethod", 0),        # 0
            135: ("CallStaticIntMethodV", 0),       # 0
            136: ("CallStaticIntMethodA", 0),       # 0
            137: ("CallStaticLongMethod", 0),       # 0
            138: ("CallStaticLongMethodV", 0),      # 0
            139: ("CallStaticLongMethodA", 0),      # 0
            140: ("CallStaticFloatMethod", 0),      # 0.0
            141: ("CallStaticFloatMethodV", 0),     # 0.0
            142: ("CallStaticFloatMethodA", 0),     # 0.0
            143: ("CallStaticDoubleMethod", 0),     # 0.0
            144: ("CallStaticDoubleMethodV", 0),    # 0.0
            145: ("CallStaticDoubleMethodA", 0),    # 0.0
            146: ("CallStaticVoidMethod", 0),       # void
            147: ("CallStaticVoidMethodV", 0),      # void
            148: ("CallStaticVoidMethodA", 0),      # void
            149: ("GetStaticObjectField", 0),       # NULL
            150: ("GetStaticBooleanField", 0),      # JNI_FALSE
            151: ("GetStaticByteField", 0),         # 0
            152: ("GetStaticCharField", 0),         # 0
            153: ("GetStaticShortField", 0),        # 0
            154: ("GetStaticIntField", 0),          # 0
            155: ("GetStaticLongField", 0),         # 0
            156: ("GetStaticFloatField", 0),        # 0.0
            157: ("GetStaticDoubleField", 0),       # 0.0
            158: ("SetStaticObjectField", 0),       # void
            159: ("SetStaticBooleanField", 0),      # void
            160: ("SetStaticByteField", 0),         # void
            161: ("SetStaticCharField", 0),         # void
            162: ("SetStaticShortField", 0),        # void
            163: ("SetStaticIntField", 0),          # void
            164: ("SetStaticLongField", 0),         # void
            165: ("SetStaticFloatField", 0),        # void
            166: ("SetStaticDoubleField", 0),       # void
            167: ("NewString", 0x2),               # non-NULL (alternate slot)
            168: ("GetStringLength", 0),            # 0
            169: ("GetStringChars", 0x3),           # non-NULL
            170: ("ReleaseStringChars", 0),         # void
            171: ("GetByteArrayElements", 0x6),     # non-NULL
            172: ("GetBooleanArrayElements", 0x6),  # non-NULL
            173: ("GetShortArrayElements", 0x6),    # non-NULL
            174: ("GetIntArrayElements", 0x6),      # non-NULL
            175: ("GetLongArrayElements", 0x6),     # non-NULL
            176: ("GetFloatArrayElements", 0x6),    # non-NULL
            177: ("GetDoubleArrayElements", 0x6),   # non-NULL
            178: ("ReleaseBooleanArrayElements", 0), # void
            179: ("ReleaseByteArrayElements", 0),    # void
            180: ("ReleaseCharArrayElements", 0),    # void
            181: ("ReleaseShortArrayElements", 0),   # void
            182: ("ReleaseIntArrayElements", 0),     # void
            183: ("ReleaseLongArrayElements", 0),    # void
            184: ("ReleaseFloatArrayElements", 0),   # void
            185: ("ReleaseDoubleArrayElements", 0),  # void
            186: ("GetBooleanArrayRegion", 0),       # void
            187: ("GetByteArrayRegion", 0),          # void
            188: ("GetCharArrayRegion", 0),          # void
            189: ("GetShortArrayRegion", 0),         # void
            190: ("GetIntArrayRegion", 0),           # void
            191: ("GetLongArrayRegion", 0),          # void
            192: ("GetFloatArrayRegion", 0),         # void
            193: ("GetDoubleArrayRegion", 0),        # void
            194: ("SetBooleanArrayRegion", 0),       # void
            195: ("SetByteArrayRegion", 0),          # void
            196: ("SetCharArrayRegion", 0),          # void
            197: ("SetShortArrayRegion", 0),         # void
            198: ("SetIntArrayRegion", 0),           # void
            199: ("SetLongArrayRegion", 0),          # void
            200: ("SetFloatArrayRegion", 0),         # void
            201: ("SetDoubleArrayRegion", 0),        # void
            202: ("RegisterNatives", 0),             # 0 = success
            203: ("UnregisterNatives", 0),           # 0 = success
            204: ("MonitorEnter", 0),                # 0 = success
            205: ("MonitorExit", 0),                 # 0 = success
            206: ("GetJavaVM", 0x1),                # non-NULL
            207: ("NewByteArray", 0x7),             # non-NULL
            208: ("GetObjectClass", 0x1),           # non-NULL
            209: ("IsInstanceOf", 0),               # JNI_FALSE
            210: ("GetMethodID", 0x1),             # non-NULL
            211: ("GetObjectField", 0),             # NULL
            212: ("GetBooleanField", 0),            # JNI_FALSE
            213: ("GetByteField", 0),               # 0
            214: ("GetCharField", 0),               # 0
            215: ("GetShortField", 0),             # 0
            216: ("GetIntField", 0),               # 0
            217: ("GetLongField", 0),              # 0
            218: ("GetFloatField", 0),             # 0.0
            219: ("GetDoubleField", 0),            # 0.0
            220: ("SetObjectField", 0),            # void
            221: ("SetBooleanField", 0),           # void
            222: ("SetByteField", 0),              # void
            223: ("SetCharField", 0),              # void
            224: ("SetShortField", 0),             # void
            225: ("SetIntField", 0),               # void
            226: ("SetLongField", 0),              # void
            227: ("SetFloatField", 0),             # void
            228: ("SetDoubleField", 0),            # void
            229: ("GetStaticMethodID", 0x1),      # non-NULL
            230: ("ExceptionCheck", 0),            # JNI_FALSE
            231: ("NewDirectByteBuffer", 0x1),    # non-NULL
        }

        # First, create a universal default stub (returns 0) for ALL slots
        default_stub = self._asm_stub_return(0)
        for idx in range(self.VTABLE_SLOTS):
            ql.mem.write(self._vtable_addr + idx * 8, struct.pack("<Q", default_stub))

        # Then overwrite specific slots with tailored return values
        for idx, (name, ret_val) in jni_functions.items():
            if idx >= self.VTABLE_SLOTS:
                continue
            stub_addr = self._asm_stub_return(ret_val)
            offset = idx * 8
            ql.mem.write(self._vtable_addr + offset, struct.pack("<Q", stub_addr))

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

    def call_function(self, input_data: bytes, timeout_us: int | None = None) -> int:
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
        timeout = timeout_us or settings.QL_TIMEOUT

        # Map input data into emulated memory
        input_size = max(len(input_data), 1)
        self._input_addr = ql.mem.map_anywhere(input_size, info="fuzz_input")
        ql.mem.write(self._input_addr, input_data)

        # Set up a return address hook
        self._return_addr = ql.mem.map_anywhere(4, info="return_addr")
        # Write RET instruction at return address
        ret_code = struct.pack("<I", 0xD65F03C0)  # ARM64 RET
        ql.mem.write(self._return_addr, ret_code)

        # Allocate a fresh stack for this invocation (1MB, 16-byte aligned)
        stack_size = 1024 * 1024  # 1 MB
        stack_base = ql.mem.map_anywhere(stack_size, info="fuzz_stack")
        # ARM64 SP must be 16-byte aligned; set SP near top of stack region
        stack_top = stack_base + stack_size - 16
        # Align down to 16 bytes
        stack_top = stack_top & ~0xF

        # Set ARM64 registers per calling convention
        ql.arch.regs.sp = stack_top
        ql.arch.regs.x0 = self.jni_porter.env_ptr_addr if self.jni_porter else 0
        ql.arch.regs.x1 = 0  # jobject = NULL
        ql.arch.regs.x2 = self._input_addr
        ql.arch.regs.x3 = len(input_data)
        ql.arch.regs.x29 = stack_top  # Frame pointer = SP
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
            err_str = str(e)
            # Infrastructure errors (MAP, FETCH) are expected in emulation
            if "UC_ERR_MAP" in err_str or "UC_ERR_FETCH" in err_str:
                logger.debug("Execution exception (infrastructure): %s", e)
            else:
                logger.warning("Execution exception: %s", e)

        # Read return value
        ret_val = -1
        if returned[0]:
            try:
                ret_val = ql.arch.regs.x0
            except Exception:
                pass
        elif exception_occurred[0]:
            err_str = str(exception_occurred[0])
            if "UC_ERR_MAP" not in err_str and "UC_ERR_FETCH" not in err_str:
                logger.warning("Function did not return normally: %s", exception_occurred[0])
            ret_val = -1
        else:
            logger.warning("Function execution timed out after %.1fs", timeout / 1_000_000)
            ret_val = -1

        # Clean up mapped memory
        try:
            ql.mem.unmap(self._input_addr, input_size)
            ql.mem.unmap(self._return_addr, 4)
            ql.mem.unmap(stack_base, stack_size)
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
