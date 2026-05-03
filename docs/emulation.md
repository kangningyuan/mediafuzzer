# emulation 模块开发文档

## 1. 模块职责

为单个原生函数提供可运行的虚拟执行环境，包括：
- SO 加载与函数调用
- JNI 桩实现（FindClass, NewStringUTF, GetMethodID 等）
- 系统调用模拟（文件 I/O、内存管理）
- 统一插桩管理（覆盖率钩子、内存安全钩子）

基于 Qiling Framework 实现。

## 2. 文件结构

```
src/emulation/
├── __init__.py            # 导出 EmulatedJNIFunc, QilingEnv
├── qiling_env.py          # Qiling 环境初始化、SO 加载、JNI 桩
├── dependency_mocker.py   # 系统调用、文件操作、libc 函数模拟
└── hook_manager.py        # 统一插桩注册、管理、解注册
```

## 3. 详细接口规格

### 3.1 qiling_env.py

```python
class EmulatedJNIFunc:
    """
    加载单个 SO 并模拟执行指定 JNI 函数。

    这是 emulation 模块的核心类，封装了 Qiling 引擎初始化、
    SO 加载、JNI 桩设置和函数调用。
    """

    def __init__(self, so_path: str, func_symbol: str,
                 rootfs: str | None = None, arch: str | None = None):
        """
        Args:
            so_path: 目标 .so 文件路径
            func_symbol: 目标函数符号名（如 "Java_com_example_Foo_bar"）
            rootfs: Android rootfs 路径，默认从 config 读取
            arch: 架构，默认 "arm64"
        """
        self.so_path = so_path
        self.func_symbol = func_symbol
        self.rootfs = rootfs or settings.QL_ROOTFS_PATH
        self.arch = arch or settings.QL_ARCH
        self.ql: Qiling | None = None
        self.hook_mgr = HookManager()
        self.dep_mocker: DependencyMocker | None = None
        self._func_addr: int | None = None

    def initialize(self) -> None:
        """
        初始化 Qiling 引擎并加载 SO。

        Steps:
        1. 创建 Qiling 实例：
           ql = Qiling(
               [self.so_path],          # 要加载的 ELF
               self.rootfs,             # rootfs 路径
               archtype=QL_ARCH.ARM64,
               ostype=QL_OS.LINUX,
               verbose=settings.QL_VERBOSE,
           )
        2. 注册 JNI 桩函数（dependency_mocker）
        3. 注册覆盖率钩子、内存安全钩子
        4. 解析目标函数地址：
           self._func_addr = ql.loader.find_symbol(self.func_symbol)
           若找不到，raise RuntimeError
        5. 执行 SO 初始化（.init_array, JNI_OnLoad 等）
        6. 设置模拟执行超时
        """
        # Qiling 初始化
        self.ql = Qiling(
            [self.so_path],
            self.rootfs,
            archtype=QL_ARCH.ARM64,
            ostype=QL_OS.LINUX,
            verbose=settings.QL_VERBOSE,
        )

        # 初始化依赖模拟
        self.dep_mocker = DependencyMocker(self.ql, self.hook_mgr)
        self.dep_mocker.setup_all()

        # 解析函数地址
        # Qiling 加载 ELF 后，符号表在 ql.loader.symbols 中
        for sym in self.ql.loader.symbols:
            if sym.name == self.func_symbol:
                self._func_addr = sym.addr
                break
        if self._func_addr is None:
            raise RuntimeError(f"Symbol '{self.func_symbol}' not found in {self.so_path}")

    def call_function(self, input_data: bytes, timeout_ms: int | None = None) -> int:
        """
        调用目标 JNI 函数，传入 input_data 作为参数。

        Args:
            input_data: 模糊测试变异后的输入数据
            timeout_ms: 超时毫秒，默认从 config 读取

        Returns:
            函数返回值（int，ARM64 的 x0 寄存器值）

        Implementation:
        1. 将 input_data 写入 Qiling 模拟内存：
           addr = self.ql.mem.map_anywhere(len(input_data) + 1)
           self.ql.mem.write(addr, input_data + b'\x00')

        2. 设置函数参数（ARM64 调用约定）：
           - x0 = JNIEnv* （指向我们构造的 JNI 环境表）
           - x1 = jobject （this 指针，通常为 NULL）
           - x2 = 输入数据地址
           - x3 = 输入数据长度（如果函数接受 byte[]）

           注意：具体参数设置取决于函数签名。
           对于常见模式 (byte[] data, int len)：
             x0 = jni_env_addr
             x1 = 0  # this
             x2 = addr  # 数据指针
             x3 = len(input_data)  # 数据长度

        3. 设置返回地址（LR 寄存器）指向一个已知地址，
           函数返回时触发钩子

        4. 调用 ql.run(begin=self._func_addr, end=return_addr,
                        timeout=timeout_ms)

        5. 读取返回值：ret = self.ql.reg.read(UC_ARM64_REG_X0)

        6. 清理映射的内存
        """
        timeout = timeout_ms or settings.QL_TIMEOUT

        # 分配内存并写入输入数据
        data_size = len(input_data)
        alloc_size = max(data_size + 1, 4096)  # 至少一页
        data_addr = self.ql.mem.map_anywhere(alloc_size)
        self.ql.mem.write(data_addr, input_data + b'\x00')

        # 设置参数
        self.ql.reg.write(UC_ARM64_REG_X0, self._jni_env_addr)
        self.ql.reg.write(UC_ARM64_REG_X1, 0)  # this = NULL
        self.ql.reg.write(UC_ARM64_REG_X2, data_addr)
        if data_size > 0:
            self.ql.reg.write(UC_ARM64_REG_X3, data_size)

        # 设置返回地址
        return_addr = self.ql.mem.map_anywhere(4)
        self.ql.mem.write(return_addr, b'\x00\x00\x00\x14')  # ARM64: B .

        # 在返回地址设置钩子停止执行
        self.ql.hook_address(self._on_return, return_addr)

        # 执行
        self.ql.run(begin=self._func_addr, end=return_addr, timeout=timeout)

        # 读取返回值
        ret_val = self.ql.reg.read(UC_ARM64_REG_X0)

        # 清理
        self.ql.mem.unmap(data_addr, alloc_size)

        return ret_val

    def _on_return(self, ql):
        """函数返回时的钩子，停止执行"""
        ql.emu_stop()

    def destroy(self) -> None:
        """清理 Qiling 引擎和所有钩子"""
        self.hook_mgr.clear_all()
        if self.ql:
            # Qiling 实例会被 GC 回收
            self.ql = None
```

### 3.2 JNI 环境构造

```python
class JNIPorter:
    """
    构造模拟的 JNI 环境表 (JNIEnv*)。

    JNI 调用通过函数指针表（vtable）实现。JNIEnv 指向一个
    JNINativeInterface_ 结构体，其中每个槽位是一个函数指针。
    我们需要将常用 JNI 函数指向我们的桩实现。
    """

    # JNI 函数表索引（来自 jni.h）
    JNI_FUNCS = {
        4:   "GetVersion",
        5:   "DefineClass",
        6:   "FindClass",
        7:   "FromReflectedMethod",
        # ... 完整表见 jni.h JNINativeInterface_
        28:  "NewStringUTF",
        29:  "GetStringUTFLength",
        30:  "GetStringUTFChars",
        31:  "ReleaseStringUTFChars",
        169: "NewByteArray",
        170: "NewIntArray",
        183: "GetByteArrayElements",
        186: "GetIntArrayElements",
        199: "ReleaseByteArrayElements",
        202: "ReleaseIntArrayElements",
        215: "GetArrayLength",
        220: "NewDirectByteBuffer",
    }

    def __init__(self, ql: Qiling):
        self.ql = ql
        self._env_addr: int | None = None
        self._vtable_addr: int | None = None

    def setup(self) -> int:
        """
        在模拟内存中构造 JNIEnv 并返回其地址。

        Structure (ARM64):
        JNIEnv** env_ptr  →  JNIEnv* env  →  JNINativeInterface_* vtable
                                                        ↓
                                              [func_ptr_0, func_ptr_1, ...]
                                                        ↓
                                              stub implementations

        Returns:
            env_ptr 地址（二级指针，传给 JNI 函数的 x0）
        """
        # 分配 vtable：232 个函数指针槽位 * 8 字节 = 1856 字节
        num_slots = 232
        vtable_size = num_slots * 8
        self._vtable_addr = self.ql.mem.map_anywhere(vtable_size)

        # 分配 JNIEnv：1 个指针指向 vtable
        env_size = 8
        self._env_addr = self.ql.mem.map_anywhere(env_size)
        self.ql.mem.write(self._env_addr,
                          struct.pack("<Q", self._vtable_addr))

        # 分配 JNIEnv**：1 个指针指向 JNIEnv
        env_ptr_size = 8
        self._env_ptr_addr = self.ql.mem.map_anywhere(env_ptr_size)
        self.ql.mem.write(self._env_ptr_addr,
                          struct.pack("<Q", self._env_addr))

        # 为每个需要桩的 JNI 函数分配桩代码
        for idx, name in self.JNI_FUNCS.items():
            stub_addr = self._create_stub(idx, name)
            self.ql.mem.write(
                self._vtable_addr + idx * 8,
                struct.pack("<Q", stub_addr),
            )

        return self._env_ptr_addr

    def _create_stub(self, func_idx: int, func_name: str) -> int:
        """
        为 JNI 函数创建 ARM64 桩代码。

        桩代码行为：
        - 记录调用日志
        - 返回合理的默认值（FindClass 返回有效类指针，NewStringUTF 返回有效字符串指针等）
        - 通过 RET 指令返回调用者
        """
        stub_addr = self.ql.mem.map_anywhere(64)  # 每个桩 64 字节足够

        if func_name == "FindClass":
            # 返回一个非 NULL 的 jclass
            code = self._asm_stub_return(1)
        elif func_name == "NewStringUTF":
            # 返回一个非 NULL 的 jstring
            code = self._asm_stub_return(2)
        elif func_name == "GetArrayLength":
            # 从 x2（数组参数）读取长度或返回默认值
            code = self._asm_stub_return(0)
        elif func_name == "GetVersion":
            # 返回 JNI 版本 0x00010006 (JNI 1.6)
            code = self._asm_stub_return(0x00010006)
        else:
            # 默认返回 0
            code = self._asm_stub_return(0)

        self.ql.mem.write(stub_addr, code)

        # 注册钩子以便在桩被调用时记录
        self.ql.hook_address(
            lambda ql, n=func_name: self._on_jni_call(n),
            stub_addr,
        )

        return stub_addr

    def _asm_stub_return(self, value: int) -> bytes:
        """
        生成返回固定值的 ARM64 桩代码。

        MOV X0, #value  (可能需要 MOVZ+MOVK)
        RET

        ARM64 encoding:
        MOVZ X0, #imm16     -> 0xD2800000 | (imm16 << 5)
        RET                 -> 0xD65F03C0
        """
        if value <= 0xFFFF:
            movz = 0xD2800000 | (value << 5)
            ret = 0xD65F03C0
            return struct.pack("<II", movz, ret)
        elif value <= 0xFFFFFFFF:
            movz = 0xD2800000 | ((value & 0xFFFF) << 5)
            movk = 0xF2A00000 | (((value >> 16) & 0xFFFF) << 5)
            ret = 0xD65F03C0
            return struct.pack("<III", movz, movk, ret)
        else:
            # 64-bit value: MOVZ + MOVK * 3
            parts = [
                0xD2800000 | ((value & 0xFFFF) << 5),
                0xF2A00000 | (((value >> 16) & 0xFFFF) << 5),
                0xF2C00000 | (((value >> 32) & 0xFFFF) << 5),
                0xF2E00000 | (((value >> 48) & 0xFFFF) << 5),
                0xD65F03C0,  # RET
            ]
            return struct.pack("<" + "I" * len(parts), *parts)
```

### 3.3 dependency_mocker.py

```python
class DependencyMocker:
    """
    模拟目标 SO 依赖的系统调用和 libc 函数。

    原生库常见的依赖：
    - 文件 I/O: fopen, fread, fwrite, fclose, fseek, ftell
    - 内存管理: malloc, calloc, realloc, free (由内存安全模块接管)
    - 字符串: strlen, strcmp, strncmp, memcpy, memset
    - 日志: __android_log_print
    - 网络: socket, connect (返回失败)
    - 线程: pthread_create, pthread_mutex_lock (返回成功但空操作)
    """

    def __init__(self, ql: Qiling, hook_mgr: 'HookManager'):
        self.ql = ql
        self.hook_mgr = hook_mgr
        self._fake_fd_counter = 1000  # 伪造文件描述符起始值
        self._fake_files: dict[int, bytes] = {}  # fd -> 文件内容
        self._fake_file_pos: dict[int, int] = {}  # fd -> 当前读取位置

    def setup_all(self) -> None:
        """注册所有系统调用和 libc 函数的钩子"""
        self._setup_file_io()
        self._setup_android_log()
        self._setup_pthread()
        self._setup_network()
        self._setup_misc()

    def _setup_file_io(self) -> None:
        """
        注册文件 I/O 函数钩子。

        fopen: 记录路径，返回伪造 fd
        fread: 从 _fake_files 读取数据
        fwrite: 记录写入（丢弃数据）
        fclose: 标记 fd 关闭
        fseek/ftell: 更新/读取文件位置
        """
        # Qiling 的 hook 函数签名：on_fopen(ql)
        # 参数通过 ql.reg.read 和 ql.mem.read 获取

        @self.hook_mgr.register("fopen")
        def on_fopen(ql):
            # ARM64: x0 = filename_ptr, x1 = mode_ptr
            filename_ptr = ql.reg.read(UC_ARM64_REG_X0)
            filename = ql.mem.read(filename_ptr, 256).split(b'\x00')[0].decode('utf-8', errors='replace')
            logging.debug(f"fopen called: {filename}")

            # 分配伪造 fd
            fd = self._fake_fd_counter
            self._fake_fd_counter += 1

            # 如果是多媒体文件路径，提供种子数据
            if any(ext in filename.lower() for ext in ['.jpg', '.jpeg', '.gif', '.png', '.webp', '.mp4']):
                self._fake_files[fd] = self._get_media_seed(filename)
            else:
                self._fake_files[fd] = b'\x00' * 4096  # 默认空数据

            self._fake_file_pos[fd] = 0

            # 返回 FILE*（用 fd 值作为标识）
            ql.reg.write(UC_ARM64_REG_X0, fd)

            # 跳过原函数（已由 Qiling 的函数钩子处理）
            # 需要调整 PC 跳过原指令
            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

    def _get_media_seed(self, filename: str) -> bytes:
        """根据文件扩展名返回对应格式的种子数据"""
        ext = filename.rsplit('.', 1)[-1].lower()
        try:
            from config.file_formats import get_format
            format_map = {'jpg': 'JPEG', 'jpeg': 'JPEG', 'gif': 'GIF',
                          'png': 'PNG', 'webp': 'WebP'}
            fmt_name = format_map.get(ext)
            if fmt_name:
                skeleton = get_format(fmt_name)
                return skeleton.generate_seed()
        except (KeyError, ImportError):
            pass
        return b'\x00' * 4096

    def _setup_android_log(self) -> None:
        """__android_log_print: 忽略日志输出，直接返回"""
        @self.hook_mgr.register("__android_log_print")
        def on_log(ql):
            ql.reg.write(UC_ARM64_REG_X0, 0)
            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

    def _setup_pthread(self) -> None:
        """pthread_*: 返回成功（0）但不实际创建线程"""
        for func_name in ["pthread_create", "pthread_mutex_lock",
                          "pthread_mutex_unlock", "pthread_mutex_init"]:
            @self.hook_mgr.register(func_name)
            def on_pthread(ql):
                ql.reg.write(UC_ARM64_REG_X0, 0)  # 0 = success
                ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

    def _setup_network(self) -> None:
        """socket/connect: 返回 -1 表示失败"""
        for func_name in ["socket", "connect", "bind", "listen"]:
            @self.hook_mgr.register(func_name)
            def on_net(ql):
                ql.reg.write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)  # -1
                ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

    def _setup_misc(self) -> None:
        """其他杂项：getenv, dlopen, dlsym 等"""
        @self.hook_mgr.register("getenv")
        def on_getenv(ql):
            # 返回 NULL 表示环境变量不存在
            ql.reg.write(UC_ARM64_REG_X0, 0)
            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))
```

### 3.4 hook_manager.py

```python
class HookManager:
    """
    统一管理所有 Qiling 钩子（覆盖率、内存安全、依赖模拟）。

    提供：
    - 按名称注册/解注册钩子
    - 按类型（coverage / memory_safety / dependency）分组管理
    - 一键清理所有钩子
    """

    def __init__(self):
        self._hooks: dict[str, dict[str, Any]] = {
            "coverage": {},
            "memory_safety": {},
            "dependency": {},
        }

    def register(self, name: str, category: str = "dependency"):
        """
        装饰器：注册钩子函数。

        Usage:
            @hook_mgr.register("fopen")
            def on_fopen(ql):
                ...
        """
        def decorator(func):
            self._hooks[category][name] = func
            return func
        return decorator

    def register_coverage_hook(self, name: str, hook_func):
        """注册覆盖率相关钩子"""
        self._hooks["coverage"][name] = hook_func

    def register_memory_hook(self, name: str, hook_func):
        """注册内存安全相关钩子"""
        self._hooks["memory_safety"][name] = hook_func

    def unregister(self, name: str, category: str | None = None) -> None:
        """
        解注册指定钩子。
        如果不指定 category，在所有分类中搜索。
        """
        if category:
            self._hooks[category].pop(name, None)
        else:
            for cat in self._hooks:
                self._hooks[cat].pop(name, None)

    def clear_category(self, category: str) -> None:
        """清除指定分类的所有钩子"""
        self._hooks[category].clear()

    def clear_all(self) -> None:
        """清除所有钩子"""
        for cat in self._hooks:
            self._hooks[cat].clear()

    def get_all_hooks(self) -> dict[str, dict]:
        """返回所有钩子的快照"""
        return self._hooks.copy()
```

## 4. 关键实现细节

### 4.1 Qiling 函数钩子机制

Qiling 支持两种钩子方式：
1. **地址钩子** (`ql.hook_address`): 在指定地址触发
2. **指令钩子** (`ql.hook_insn`): 在指定指令类型触发
3. **内存访问钩子** (`ql.hook_mem_read`, `ql.hook_mem_write`): 在内存读写时触发

对于 libc 函数模拟，Qiling 内部已有部分实现（`ql.os.lua` 或 `ql.os.func_hook`）。需要检查 Qiling 版本的 API：
- Qiling 1.4.5+: 使用 `ql.os.set_api(func_name, callback)` 注册函数钩子
- 钩子回调签名：`def callback(ql, *args): ...`

### 4.2 ARM64 调用约定

| 寄存器 | 用途 |
|--------|------|
| X0-X7 | 函数参数 / 返回值 (X0) |
| X8 | 间接结果地址 |
| X9-X15 | 临时寄存器 |
| X16-X17 | IP0/IP1 (PLT) |
| X18 | 平台寄存器 |
| X19-X28 | 被调用者保存 |
| X29 (FP) | 帧指针 |
| X30 (LR) | 返回地址 |
| SP | 栈指针 |

### 4.3 内存布局

```
高地址
├────────────────┤
│    Stack       │  ← SP
│    (向下增长)   │
├────────────────┤
│                │
│   (空闲空间)    │
│                │
├────────────────┤
│  Input Data    │  ← map_anywhere 分配
├────────────────┤
│  JNI Env       │  ← JNIPorter 分配
├────────────────┤
│  SO + libc     │  ← Qiling 自动加载
├────────────────┤
低地址
```

### 4.4 超时处理

Qiling 支持 `timeout` 参数（毫秒）。超时后 `ql.run()` 会自动停止。需要在 `call_function` 中处理 `QlErrorExecutionStop` 等异常。

## 5. 跨模块依赖

- **依赖**: `config.settings` (QL_* 配置, rootfs 路径), `config.file_formats` (种子生成)
- **被依赖**:
  - `fuzzing` (使用 EmulatedJNIFunc 执行变异输入)
  - `memory_safety` (通过 HookManager 注册内存安全钩子)
  - `fuzzing.coverage` (通过 HookManager 注册覆盖率钩子)

## 6. 错误处理

| 异常场景 | 处理方式 |
|---------|---------|
| SO 文件不存在 | raise FileNotFoundError |
| rootfs 不存在 | raise RuntimeError("Rootfs not found") |
| 函数符号未找到 | raise RuntimeError("Symbol not found") |
| Qiling 初始化失败 | raise，记录详细错误 |
| 模拟执行超时 | 返回特殊值 -1，记录 warning |
| 内存映射失败 | raise MemoryError |
| JNI 桩崩溃 | 捕获异常，记录日志，尝试恢复 |
| 无效内存访问 | 触发 Qiling 的 mem_invalid 钩子，记录并跳过 |

## 7. 实现步骤

1. **Step 1**: 实现 `hook_manager.py` — 最简单的模块，先确保钩子管理基础设施可用
2. **Step 2**: 实现 `JNIPorter` — JNI 环境构造，用极简 SO 测试
3. **Step 3**: 实现 `dependency_mocker.py` — 文件 I/O 和 Android 日志模拟
4. **Step 4**: 实现 `EmulatedJNIFunc.initialize()` — SO 加载和函数地址解析
5. **Step 5**: 实现 `EmulatedJNIFunc.call_function()` — 完整的函数调用流程
6. **Step 6**: 用 `int add(int a, int b)` 极简 SO 测试完整流程
7. **Step 7**: 用含 JNI 调用的 SO 测试 JNI 桩
8. **Step 8**: 测试文件系统模拟

## 8. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| 极简 SO 加载 | 加载含 `add()` 的 SO | 成功初始化，函数地址非零 |
| 极简 SO 调用 | 调用 `add(2, 3)` | 返回 5 |
| JNI SO 加载 | 加载含 JNI 函数的 SO | 成功初始化 |
| FindClass 桩 | 调用含 FindClass 的函数 | 不崩溃，返回非 NULL |
| NewStringUTF 桩 | 调用含 NewStringUTF 的函数 | 不崩溃 |
| fopen 模拟 | 函数内调用 fopen | 返回有效 FILE* |
| fread 模拟 | fopen 后 fread | 返回种子数据 |
| 超时处理 | 设置超时 1ms 执行长循环 | 超时返回，不挂起 |
| 无效内存访问 | 函数访问 NULL 指针 | 触发 mem_invalid 钩子，不崩溃 |
| 1000 轮稳定性 | 循环调用 1000 次 | 无内存泄漏，无崩溃 |
