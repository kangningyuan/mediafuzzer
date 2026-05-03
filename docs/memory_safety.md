# memory_safety 模块开发文档

## 1. 模块职责

实现基于标记指针（Tagged Pointer）的主动内存异常检测，替代依赖进程崩溃的被动检测。通过在模拟执行环境中维护内存状态表，主动发现：
- 缓冲区溢出（越界读写）
- 释放后使用（Use-After-Free, UAF）
- 双重释放（Double Free）
- 未初始化内存读取

## 2. 文件结构

```
src/memory_safety/
├── __init__.py          # 导出 MemorySafetyChecker, TagBasedDetector
├── tag_based.py         # 基于标记指针的主动检测
└── sanitizer_hooks.py   # 挂钩分配/释放/内存访问函数
```

## 3. 核心原理

### 3.1 标记指针（Tagged Pointer）

在 ARM64 架构中，地址的高16位（bit 48-63）在虚拟地址中通常未使用（TBI: Top Byte Ignore）。我们利用这16位编码一个随机标签（tag）：

```
 63           48 47                                        0
┌──────────────┬────────────────────────────────────────────┐
│   TAG (16b)  │           ADDRESS (48b)                    │
└──────────────┴────────────────────────────────────────────┘
```

每次内存分配时：
1. 生成随机标签
2. 在返回的指针中编码标签
3. 在内存状态表中记录 (base_addr, size, tag, freed)

每次内存访问时：
1. 从指针中提取标签
2. 在状态表中查找目标内存块
3. 比较标签是否匹配
4. 检查是否越界或已释放

### 3.2 内存状态表

```python
@dataclass
class MemBlock:
    base_addr: int        # 分配基址（去除标签后的真实地址）
    size: int             # 分配大小
    tag: int              # 随机标签（16位）
    freed: bool           # 是否已释放
    alloc_caller: int     # 分配时的调用地址
    free_caller: int      # 释放时的调用地址（若已释放）
    alloc_time: float     # 分配时间戳
    free_time: float      # 释放时间戳（若已释放）

class MemoryStateTable:
    """
    全局内存状态表，记录所有已分配内存块的元数据。

    查询方式：
    - 按地址查找：给定一个指针，找到包含该地址的内存块
    - 按标签查找：给定标签，找到对应的所有内存块
    """

    def __init__(self):
        self._blocks: dict[int, MemBlock] = {}   # base_addr -> MemBlock
        self._tag_index: dict[int, list[int]] = {}  # tag -> [base_addr, ...]

    def allocate(self, size: int, caller_addr: int) -> tuple[int, int]:
        """
        分配新内存块。

        Returns:
            (tagged_ptr, tag) — 带标签的指针和标签值
        """
        tag = random.randint(1, 0xFFFF)  # 标签 0 保留（表示无标签）
        # 实际分配由 Qiling 的内存管理处理
        # 这里只记录元数据
        # ...

    def lookup(self, addr: int) -> MemBlock | None:
        """根据地址查找包含该地址的内存块"""
        for base, block in self._blocks.items():
            if base <= addr < base + block.size:
                return block
        return None

    def free(self, addr: int, caller_addr: int) -> MemBlock | None:
        """标记内存块为已释放"""
        block = self.lookup(addr)
        if block:
            block.freed = True
            block.free_caller = caller_addr
            block.free_time = time.time()
        return block
```

## 4. 详细接口规格

### 4.1 tag_based.py

```python
class TagBasedDetector:
    """
    基于标记指针的主动内存异常检测器。

    在 Qiling 模拟环境中拦截内存分配/释放/访问，
    通过标签验证和边界检查主动发现内存安全漏洞。
    """

    TAG_BITS = 16
    TAG_MASK = 0xFFFF << 48
    ADDR_MASK = (1 << 48) - 1

    def __init__(self, ql: Qiling, hook_mgr: HookManager):
        self.ql = ql
        self.hook_mgr = hook_mgr
        self.state_table = MemoryStateTable()
        self._violations: list[dict] = []
        self._tag_counter = 1  # 标签计数器（避免随机碰撞）

    def extract_tag(self, ptr: int) -> int:
        """从指针中提取标签（高16位）"""
        return (ptr >> 48) & 0xFFFF

    def extract_addr(self, ptr: int) -> int:
        """从指针中提取真实地址（低48位）"""
        return ptr & self.ADDR_MASK

    def encode_tag(self, addr: int, tag: int) -> int:
        """将标签编码到指针的高16位"""
        return (tag << 48) | (addr & self.ADDR_MASK)

    def generate_tag(self) -> int:
        """生成新的唯一标签"""
        tag = self._tag_counter
        self._tag_counter = (self._tag_counter % 0xFFFF) + 1
        return tag

    def check_access(self, ptr: int, access_size: int, access_type: str) -> dict | None:
        """
        检查内存访问是否安全。

        Args:
            ptr: 访问的指针（可能带标签）
            access_size: 访问大小（字节）
            access_type: "read" 或 "write"

        Returns:
            None = 安全
            dict = 违规信息 {
                "type": "overflow" | "uaf" | "tag_mismatch",
                "ptr": ptr,
                "real_addr": ...,
                "block_base": ...,
                "block_size": ...,
                "tag_expected": ...,
                "tag_actual": ...,
                "access_type": ...,
            }
        """
        tag = self.extract_tag(ptr)
        real_addr = self.extract_addr(ptr)

        # 无标签的指针（tag=0）跳过检查
        if tag == 0:
            return None

        # 查找包含该地址的内存块
        block = self.state_table.lookup(real_addr)

        if block is None:
            # 未知内存区域，可能是全局/栈变量，跳过
            return None

        # 检查1: 标签匹配
        if block.tag != tag:
            return {
                "type": "tag_mismatch",
                "ptr": ptr,
                "real_addr": real_addr,
                "block_base": block.base_addr,
                "block_size": block.size,
                "tag_expected": block.tag,
                "tag_actual": tag,
                "access_type": access_type,
                "description": f"Tag mismatch: expected {block.tag:#x}, got {tag:#x}. "
                              f"Possible use-after-free or pointer corruption.",
            }

        # 检查2: 已释放
        if block.freed:
            return {
                "type": "uaf",
                "ptr": ptr,
                "real_addr": real_addr,
                "block_base": block.base_addr,
                "block_size": block.size,
                "tag_expected": block.tag,
                "tag_actual": tag,
                "access_type": access_type,
                "description": f"Use-after-free: accessing freed memory at {real_addr:#x}",
            }

        # 检查3: 越界
        access_end = real_addr + access_size
        block_end = block.base_addr + block.size
        if real_addr < block.base_addr or access_end > block_end:
            return {
                "type": "overflow",
                "ptr": ptr,
                "real_addr": real_addr,
                "block_base": block.base_addr,
                "block_size": block.size,
                "tag_expected": block.tag,
                "tag_actual": tag,
                "access_type": access_type,
                "description": f"Buffer overflow: accessing [{real_addr:#x}, {access_end:#x}) "
                              f"outside block [{block.base_addr:#x}, {block_end:#x})",
            }

        return None

    def get_violations(self) -> list[dict]:
        """获取所有检测到的违规"""
        return self._violations.copy()

    def clear_violations(self) -> None:
        """清除违规记录"""
        self._violations.clear()
```

### 4.2 sanitizer_hooks.py

```python
class SanitizerHooks:
    """
    在 Qiling 中挂钩内存分配/释放和内存访问函数，
    将 TagBasedDetector 集成到模拟执行流程中。
    """

    def __init__(self, ql: Qiling, detector: TagBasedDetector, hook_mgr: HookManager):
        self.ql = ql
        self.detector = detector
        self.hook_mgr = hook_mgr

    def install(self) -> None:
        """安装所有钩子"""
        self._hook_allocators()
        self._hook_deallocators()
        self._hook_memory_access()

    def _hook_allocators(self) -> None:
        """挂钩 malloc, calloc, realloc"""

        @self.hook_mgr.register("malloc", "memory_safety")
        def on_malloc(ql):
            size = ql.reg.read(UC_ARM64_REG_X0)

            # 分配内存（使用 Qiling 的内存映射）
            # 对齐到页边界
            alloc_size = max(size, 16)
            alloc_size = (alloc_size + 0xFFF) & ~0xFFF  # 向上对齐到页

            # 在 Qiling 中映射内存
            base_addr = ql.mem.map_anywhere(alloc_size)

            # 生成标签
            tag = self.detector.generate_tag()

            # 记录到状态表
            self.detector.state_table._blocks[base_addr] = MemBlock(
                base_addr=base_addr,
                size=size,
                tag=tag,
                freed=False,
                alloc_caller=ql.reg.read(UC_ARM64_REG_LR),
                free_caller=0,
                alloc_time=time.time(),
                free_time=0,
            )

            # 编码标签到返回指针
            tagged_ptr = self.detector.encode_tag(base_addr, tag)

            # 返回带标签的指针
            ql.reg.write(UC_ARM64_REG_X0, tagged_ptr)

            # 跳过原函数
            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

        @self.hook_mgr.register("calloc", "memory_safety")
        def on_calloc(ql):
            nmemb = ql.reg.read(UC_ARM64_REG_X0)
            size = ql.reg.read(UC_ARM64_REG_X1)
            total = nmemb * size

            # 分配并清零
            alloc_size = max(total, 16)
            alloc_size = (alloc_size + 0xFFF) & ~0xFFF
            base_addr = ql.mem.map_anywhere(alloc_size)
            ql.mem.write(base_addr, b'\x00' * alloc_size)

            tag = self.detector.generate_tag()
            self.detector.state_table._blocks[base_addr] = MemBlock(
                base_addr=base_addr,
                size=total,
                tag=tag,
                freed=False,
                alloc_caller=ql.reg.read(UC_ARM64_REG_LR),
                free_caller=0,
                alloc_time=time.time(),
                free_time=0,
            )

            tagged_ptr = self.detector.encode_tag(base_addr, tag)
            ql.reg.write(UC_ARM64_REG_X0, tagged_ptr)
            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

        @self.hook_mgr.register("realloc", "memory_safety")
        def on_realloc(ql):
            old_ptr = ql.reg.read(UC_ARM64_REG_X0)
            new_size = ql.reg.read(UC_ARM64_REG_X1)

            # 提取旧标签和地址
            old_tag = self.detector.extract_tag(old_ptr)
            old_addr = self.detector.extract_addr(old_ptr)

            # 分配新内存
            alloc_size = max(new_size, 16)
            alloc_size = (alloc_size + 0xFFF) & ~0xFFF
            new_base = ql.mem.map_anywhere(alloc_size)

            # 复制旧数据
            if old_addr != 0:
                old_block = self.detector.state_table.lookup(old_addr)
                if old_block and not old_block.freed:
                    copy_size = min(old_block.size, new_size)
                    data = ql.mem.read(old_addr, copy_size)
                    ql.mem.write(new_base, bytes(data))

                    # 标记旧块为已释放
                    old_block.freed = True
                    old_block.free_caller = ql.reg.read(UC_ARM64_REG_LR)
                    old_block.free_time = time.time()

            # 生成新标签
            new_tag = self.detector.generate_tag()
            self.detector.state_table._blocks[new_base] = MemBlock(
                base_addr=new_base,
                size=new_size,
                tag=new_tag,
                freed=False,
                alloc_caller=ql.reg.read(UC_ARM64_REG_LR),
                free_caller=0,
                alloc_time=time.time(),
                free_time=0,
            )

            tagged_ptr = self.detector.encode_tag(new_base, new_tag)
            ql.reg.write(UC_ARM64_REG_X0, tagged_ptr)
            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

    def _hook_deallocators(self) -> None:
        """挂钩 free"""

        @self.hook_mgr.register("free", "memory_safety")
        def on_free(ql):
            ptr = ql.reg.read(UC_ARM64_REG_X0)
            tag = self.detector.extract_tag(ptr)
            real_addr = self.detector.extract_addr(ptr)

            if real_addr == 0:
                # free(NULL) 是合法的
                ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))
                return

            block = self.detector.state_table.lookup(real_addr)

            if block is None:
                # 释放未知内存
                self.detector._violations.append({
                    "type": "invalid_free",
                    "ptr": ptr,
                    "real_addr": real_addr,
                    "description": f"Free of unallocated memory at {real_addr:#x}",
                })
            elif block.freed:
                # 双重释放
                self.detector._violations.append({
                    "type": "double_free",
                    "ptr": ptr,
                    "real_addr": real_addr,
                    "block_base": block.base_addr,
                    "description": f"Double free at {real_addr:#x}, "
                                  f"first freed at {block.free_caller:#x}",
                })
            elif block.tag != tag:
                # 标签不匹配
                self.detector._violations.append({
                    "type": "tag_mismatch_free",
                    "ptr": ptr,
                    "real_addr": real_addr,
                    "tag_expected": block.tag,
                    "tag_actual": tag,
                    "description": f"Free with mismatched tag: expected {block.tag:#x}, got {tag:#x}",
                })
            else:
                # 正常释放
                block.freed = True
                block.free_caller = ql.reg.read(UC_ARM64_REG_LR)
                block.free_time = time.time()

            ql.reg.write(UC_ARM64_REG_PC, ql.reg.read(UC_ARM64_REG_LR))

    def _hook_memory_access(self) -> None:
        """
        挂钩内存读写操作。

        使用 Qiling 的 hook_mem_read / hook_mem_write：
        在每次内存访问时，检查访问的指针是否带有标签，
        如果有则验证标签和边界。
        """

        def on_mem_access(ql, access_type, addr, size, value):
            # 检查访问地址是否落在带标签的内存块中
            # 注意：这里 addr 是被访问的地址（不含标签），
            # 我们需要回溯源寄存器来获取带标签的指针。
            # 简化实现：对所有已知分配的内存块检查边界
            block = self.detector.state_table.lookup(addr)
            if block and block.freed:
                self.detector._violations.append({
                    "type": "uaf",
                    "ptr": addr,
                    "real_addr": addr,
                    "block_base": block.base_addr,
                    "access_type": "read" if access_type == UC_MEM_READ else "write",
                    "description": f"Use-after-free: accessing freed memory at {addr:#x}",
                })

        self.ql.hook_mem_read(on_mem_access)
        self.ql.hook_mem_write(on_mem_access)
```

## 5. 关键实现细节

### 5.1 标签编码在 ARM64 中的可行性

ARM64 的 TBI (Top Byte Ignore) 特性使得硬件忽略地址的高8位。但我们需要16位标签，超出了硬件 TBI 的范围。在模拟环境中这不构成问题——我们完全控制地址解析逻辑。

**关键**：在 Qiling 中，所有地址计算都由 Unicorn 引擎处理。当我们返回带标签的指针时，目标 SO 代码会使用该指针进行内存访问。Unicorn 不会忽略高16位，因此我们需要在目标代码使用指针前剥离标签。

**方案**：在 Qiling 的内存访问钩子中，检测到带标签的地址后，自动剥离标签并重定向到真实地址。这需要深度集成 Qiling 的内存访问回调。

**替代方案（推荐用于M5阶段）**：不修改指针格式，而是在内存状态表中仅记录分配信息和边界，通过 Qiling 的 `hook_mem_read`/`hook_mem_write` 进行边界检查。标签检查仅在 malloc/free 入口处进行（通过比对调用栈）。

### 5.2 与被动检测的对比

| 特性 | 被动检测（崩溃） | 主动检测（标记指针） |
|------|----------------|-------------------|
| 检测时机 | 崩溃时 | 内存访问时 |
| UAF 检测 | 依赖地址空间重用 | 立即检测（标签不匹配） |
| 溢出检测 | 依赖页保护 | 精确边界检查 |
| 误报率 | 低 | 需要仔细调优 |
| 性能开销 | 低 | 中等（每次访问都检查） |
| 漏报率 | 高（不崩溃的漏洞） | 低 |

### 5.3 CWE 漏洞类型与检测策略

| CWE | 漏洞类型 | 检测方式 |
|-----|---------|---------|
| CWE-122 | 堆缓冲区溢出 | 边界检查：访问地址超出分配块范围 |
| CWE-415 | 双重释放 | 状态检查：释放已标记为 freed 的块 |
| CWE-416 | 释放后使用 | 标签检查：访问已释放的内存块 |
| CWE-787 | 越界写入 | 边界检查：写入地址超出分配块范围 |
| CWE-125 | 越界读取 | 边界检查：读取地址超出分配块范围 |

## 6. 跨模块依赖

- **依赖**: `emulation` (Qiling 实例, HookManager), `config.settings` (MEM_SAFETY_ENABLED, MEM_TAG_BITS)
- **被依赖**: `fuzzing` (FuzzWorker 收集内存违规), `reporter` (违规信息进入报告)

## 7. 错误处理

| 异常场景 | 处理方式 |
|---------|---------|
| 内存状态表查找失败 | 跳过检查（可能是栈/全局变量） |
| 标签为0 | 跳过检查（无标签指针） |
| 内存映射失败 | raise，中断执行 |
| 同一地址多次分配 | 记录 warning，覆盖旧条目 |

## 8. 实现步骤

1. **Step 1**: 实现 `MemoryStateTable` — 内存状态表数据结构
2. **Step 2**: 实现 `TagBasedDetector` — 标签编解码和检查逻辑
3. **Step 3**: 实现 `SanitizerHooks._hook_allocators()` — malloc/calloc/realloc 钩子
4. **Step 4**: 实现 `SanitizerHooks._hook_deallocators()` — free 钩子
5. **Step 5**: 实现 `SanitizerHooks._hook_memory_access()` — 内存访问钩子
6. **Step 6**: 用 Juliet CWE-122 测试集验证溢出检测
7. **Step 7**: 用 Juliet CWE-415 测试集验证双重释放检测
8. **Step 8**: 用 Juliet CWE-416 测试集验证 UAF 检测
9. **Step 9**: 性能测试，确保开销 < 2x

## 9. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| malloc 记录 | 分配内存 | 状态表中有新条目，标签非零 |
| free 标记 | 释放内存 | 状态表中 freed=True |
| 双重释放检测 | 连续两次 free | 检测到 double_free 违规 |
| UAF 检测 | free 后读取 | 检测到 uaf 违规 |
| 溢出检测 | 写入超出分配大小 | 检测到 overflow 违规 |
| 标签编码 | encode_tag(addr, tag) | 高16位=tag, 低48位=addr |
| 标签解码 | extract_tag/extract_addr | 正确提取标签和地址 |
| CWE-122 检出 | Juliet 堆溢出测试集 | 检出数量 >= 论文报告 |
| CWE-415 检出 | Juliet 双重释放测试集 | 检出数量 >= 论文报告 |
| CWE-416 检出 | Juliet UAF 测试集 | 检出数量 >= 论文报告 |
| 性能开销 | 带检测 vs 不带检测 | < 2x 内存和时间开销 |
| 被动 vs 主动对比 | 同一测试集 | 主动检测检出数 > 被动检测 |
