# tools 辅助工具开发文档

## 1. 模块职责

提供 C/C++ 辅助工具，包括：
- LibFuzzer 驱动的 C 模板及编译脚本
- 覆盖率插桩运行时（Qiling 钩子优化版）

## 2. 文件结构

```
tools/
├── libfuzzer_harness/
│   ├── harness_template.c   # LibFuzzer 驱动 C 模板
│   ├── CMakeLists.txt       # CMake 构建配置
│   └── build.sh             # 一键编译脚本
└── coverage_runtime/
    └── coverage.c           # 覆盖率插桩运行时
```

## 3. 详细规格

### 3.1 harness_template.c

LibFuzzer 测试驱动的 C 模板。由 `src/fuzzing/harness.py` 填充参数后编译。

```c
// harness_template.c
// LibFuzzer 测试驱动模板
// 由 MediaFuzzer 自动生成并编译

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// ============================================================
// 配置（由 harness.py 填充）
// ============================================================

// 覆盖率位图大小
#define COV_BITMAP_SIZE {{COV_BITMAP_SIZE}}

// 目标函数名（用于标识）
#define TARGET_FUNC "{{TARGET_FUNC}}"

// ============================================================
// Python 回调接口
// ============================================================

// 回调函数类型定义
// Python 侧通过 ctypes 设置此回调
// 返回值: 0=正常执行, -1=检测到异常, 1=需要保留此输入(新覆盖)
typedef int (*fuzz_callback_t)(const uint8_t *data, size_t size);

// 全局回调指针
static fuzz_callback_t g_fuzz_callback = NULL;

// 设置回调（由 Python ctypes 调用）
void set_fuzz_callback(fuzz_callback_t cb) {
    g_fuzz_callback = cb;
}

// ============================================================
// 覆盖率位图
// ============================================================

// __libfuzzer_extra_counters 是 LibFuzzer 识别的特殊符号
// LibFuzzer 会在覆盖率引导决策中自动读取此数组
uint8_t __libfuzzer_extra_counters[COV_BITMAP_SIZE];

// 重置覆盖率位图（每轮测试前调用）
void reset_coverage_bitmap(void) {
    memset(__libfuzzer_extra_counters, 0, COV_BITMAP_SIZE);
}

// 获取位图指针（供 Python 侧读取覆盖率数据）
uint8_t* get_coverage_bitmap(void) {
    return __libfuzzer_extra_counters;
}

// ============================================================
// 自定义变异器
// ============================================================

// 外部自定义变异函数（由 Python 侧通过 ctypes 实现）
// 如果未设置，LLVMFuzzerCustomMutator 将回退到默认变异
typedef size_t (*custom_mutator_t)(
    uint8_t *data, size_t size, size_t max_size, unsigned int seed);

static custom_mutator_t g_custom_mutator = NULL;

void set_custom_mutator(custom_mutator_t mut) {
    g_custom_mutator = mut;
}

// LibFuzzer 自定义变异器入口
size_t LLVMFuzzerCustomMutator(
    uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
    if (g_custom_mutator) {
        return g_custom_mutator(data, size, max_size, seed);
    }
    // 回退：不使用自定义变异，让 LibFuzzer 使用默认策略
    // 返回 0 表示不修改
    return size;
}

// ============================================================
// LibFuzzer 主入口
// ============================================================

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_fuzz_callback || size < 1) {
        return 0;
    }

    // 重置覆盖率位图
    reset_coverage_bitmap();

    // 调用 Python 侧的 Qiling 模拟执行
    int result = g_fuzz_callback(data, size);

    return result;
}

// ============================================================
// 可选：自定义合并策略
// ============================================================

// 用于语料库精简时的自定义合并逻辑
size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *data1, size_t size1,
    const uint8_t *data2, size_t size2,
    uint8_t *out, size_t max_out_size,
    unsigned int seed) {
    // 简单实现：交替复制
    size_t out_size = 0;
    const uint8_t *src[2] = {data1, data2};
    size_t sizes[2] = {size1, size2};
    unsigned int idx = seed % 2;

    while (out_size < max_out_size) {
        if (out_size < sizes[idx]) {
            out[out_size] = src[idx][out_size];
            out_size++;
        }
        idx = 1 - idx;
        if (out_size >= sizes[0] && out_size >= sizes[1]) break;
    }

    return out_size;
}
```

### 3.2 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.16)
project(mediafuzzer_harness C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

# 查找 Clang（优先使用配置中指定的版本）
if(DEFINED ENV{CLANG_PATH})
    set(CMAKE_C_COMPILER "$ENV{CLANG_PATH}")
else()
    find_program(CLANG "clang-18" "clang-16" "clang-14" "clang")
    if(CLANG)
        set(CMAKE_C_COMPILER ${CLANG})
    endif()
endif()

# LibFuzzer 选项
set(FUZZER_FLAGS "-fsanitize=fuzzer-no-link")

# 覆盖率位图大小（可通过 -D 覆盖）
if(NOT DEFINED COV_BITMAP_SIZE)
    set(COV_BITMAP_SIZE 65536)
endif()

# 配置编译选项
add_library(harness SHARED harness_template.c)
target_compile_options(harness PRIVATE ${FUZZER_FLAGS})
target_compile_definitions(harness PRIVATE
    COV_BITMAP_SIZE=${COV_BITMAP_SIZE}
    TARGET_FUNC="default"
)

# 安装目标
install(TARGETS harness DESTINATION lib)
```

### 3.3 build.sh

```bash
#!/bin/bash
# build.sh - 一键编译 LibFuzzer harness
#
# 用法:
#   ./build.sh [CLANG_PATH] [COV_BITMAP_SIZE]
#
# 环境变量:
#   CLANG_PATH       - Clang 编译器路径（默认: /usr/bin/clang-18）
#   COV_BITMAP_SIZE  - 覆盖率位图大小（默认: 65536）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

CLANG_PATH="${1:-${CLANG_PATH:-/usr/bin/clang-18}}"
COV_BITMAP_SIZE="${2:-${COV_BITMAP_SIZE:-65536}}"

echo "=== MediaFuzzer Harness Build ==="
echo "Clang: ${CLANG_PATH}"
echo "Coverage bitmap size: ${COV_BITMAP_SIZE}"
echo ""

# 验证 Clang 存在
if ! command -v "${CLANG_PATH}" &>/dev/null; then
    echo "ERROR: Clang not found at ${CLANG_PATH}"
    exit 1
fi

# 创建构建目录
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# CMake 配置
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_C_COMPILER="${CLANG_PATH}" \
    -DCOV_BITMAP_SIZE="${COV_BITMAP_SIZE}" \
    -DCMAKE_BUILD_TYPE=Release

# 编译
cmake --build "${BUILD_DIR}" -j"$(nproc)"

echo ""
echo "=== Build Complete ==="
echo "Output: ${BUILD_DIR}/libharness.so"
```

### 3.4 coverage.c

覆盖率插桩运行时，提供与 Qiling 钩子交互的高效接口。

```c
// coverage.c
// 覆盖率插桩运行时
// 提供高效的基本块覆盖率记录接口

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// 覆盖率位图（与 LibFuzzer 的 __libfuzzer_extra_counters 共享）
#ifndef COV_BITMAP_SIZE
#define COV_BITMAP_SIZE 65536
#endif

extern uint8_t __libfuzzer_extra_counters[COV_BITMAP_SIZE];

// 上一个基本块的哈希（用于边覆盖）
static uint32_t g_prev_hash = 0;

// 记录基本块访问
// 由 Qiling 的基本块钩子通过 ctypes 调用
void cov_trace_pc(uintptr_t pc) {
    // 计算当前块哈希
    uint32_t curr_hash = (uint32_t)(pc >> 4) ^ ((uint32_t)(pc) << 8);

    // 计算边索引
    uint32_t edge_idx = (g_prev_hash ^ curr_hash) % COV_BITMAP_SIZE;

    // 更新位图（AFL 风格命中计数）
    if (__libfuzzer_extra_counters[edge_idx] < 255) {
        __libfuzzer_extra_counters[edge_idx]++;
    }

    // 更新前驱哈希（AFL 风格 ROR）
    g_prev_hash = (curr_hash >> 1);
}

// 重置覆盖率状态
void cov_reset(void) {
    memset(__libfuzzer_extra_counters, 0, COV_BITMAP_SIZE);
    g_prev_hash = 0;
}

// 获取已覆盖的边数
uint32_t cov_get_covered_count(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < COV_BITMAP_SIZE; i++) {
        if (__libfuzzer_extra_counters[i] > 0) count++;
    }
    return count;
}

// 获取覆盖率比例（千分比）
uint32_t cov_get_coverage_per_mille(void) {
    return (cov_get_covered_count() * 1000) / COV_BITMAP_SIZE;
}
```

## 4. 关键实现细节

### 4.1 __libfuzzer_extra_counters 机制

LibFuzzer 从 LLVM 12 开始支持 `__libfuzzer_extra_counters` 全局数组。当此符号存在时，LibFuzzer 会：
1. 在覆盖率引导决策中读取此数组
2. 数组中非零元素表示对应的覆盖率点被命中
3. LibFuzzer 将这些额外的覆盖率点纳入其语料库管理

这使得 Python 侧（Qiling）收集的覆盖率能够直接影响 LibFuzzer 的变异决策。

### 4.2 ctypes 桥接

Python 与 C 共享库的交互通过 ctypes 实现：

```python
import ctypes

# 加载 harness
lib = ctypes.CDLL("./build/libharness.so")

# 设置回调
CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
callback = CALLBACK(python_callback_func)
lib.set_fuzz_callback(callback)

# 访问覆盖率位图
bitmap_size = 65536
bitmap_type = ctypes.c_uint8 * bitmap_size
bitmap = bitmap_type.from_address(ctypes.addressof(lib.__libfuzzer_extra_counters))

# 读取覆盖率
covered = sum(1 for i in range(bitmap_size) if bitmap[i] > 0)
```

### 4.3 编译选项

| 选项 | 作用 |
|------|------|
| `-fsanitize=fuzzer-no-link` | 编译 LibFuzzer 运行时但不链接主循环 |
| `-shared -fPIC` | 编译为位置无关共享库 |
| `-fsanitize=address` | 可选：启用 ASan（与主动检测互补） |
| `-O2` | 优化（但不过度优化，保留覆盖率插桩） |

## 5. 跨模块依赖

- **被依赖**: `fuzzing/harness.py` (编译和使用 harness), `fuzzing/coverage.py` (使用 coverage.c 接口)

## 6. 实现步骤

1. **Step 1**: 编写 `harness_template.c`，使用占位符
2. **Step 2**: 编写 `CMakeLists.txt`
3. **Step 3**: 编写 `build.sh`
4. **Step 4**: 手动编译验证，确保 `libharness.so` 可生成
5. **Step 5**: 编写 `coverage.c`
6. **Step 6**: 用 ctypes 测试覆盖率位图共享
7. **Step 7**: 集成到 `fuzzing/harness.py` 的编译流程

## 7. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| 编译 harness | 执行 build.sh | 生成 libharness.so |
| ctypes 加载 | Python 加载 .so | 无报错 |
| 设置回调 | set_fuzz_callback | 回调可被调用 |
| 覆盖率位图共享 | Python 读取位图 | 初始全零 |
| cov_trace_pc | 调用后读取位图 | 对应位置非零 |
| cov_reset | 重置后读取 | 全零 |
| 完整循环 | Python 调用 LLVMFuzzerTestOneInput | 正常执行 |
