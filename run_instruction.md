# MediaFuzzer 测试流程操作指南

本文档描述从零开始运行 MediaFuzzer 完整测试流程的每一步操作，包括环境准备、依赖安装、配置、构建和各阶段测试。

---

## 1. 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux (WSL2 / Ubuntu 22.04+ 已验证) |
| Python | 3.12+ |
| Clang | clang-18 (需支持 `--target=aarch64-linux-gnu` 交叉编译) |
| 磁盘空间 | ≥ 500MB (含 rootfs、APK、输出) |

### 1.1 系统依赖

```bash
# Clang-18 (用于 harness 交叉编译)
sudo apt-get install -y clang-18 lld-18

# binutils-aarch64 (ARM64 交叉链接器，可选，clang+lld 可替代)
sudo apt-get install -y binutils-aarch64-linux-gnu
```

### 1.2 Python 环境

```bash
cd /home/kangning/mediafuzzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 重要：setuptools 必须 <71，否则 unicorn/capstone 的 pkg_resources 导入失败
pip install "setuptools<71"
```

验证安装：

```bash
python3 -c "from qiling import Qiling; print('Qiling OK')"
python3 -c "from capstone import Cs, CS_ARCH_ARM64; print('Capstone OK')"
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools OK')"
python3 -c "from androguard.core.apk import APK; print('Androguard OK')"
clang-18 --version
```

---

## 2. 配置

### 2.1 LLM API 密钥

在项目根目录创建 `.env` 文件：

```bash
cat > .env << 'EOF'
OPENAI_API_KEY=<你的API密钥>
LLM_API_BASE=<兼容OpenAI协议的API端点>
LLM_MODEL_NAME=<模型名称>
EOF
```

当前项目使用火山引擎（ByteDance）端点，兼容 OpenAI 协议。`settings.py` 会从 `.env` 自动加载，环境变量优先级：`env vars > .env > 代码默认值`。

关键映射关系（见 `config/settings.py` 的 `_apply_env_overrides`）：

| 环境变量 | 配置项 | 说明 |
|----------|--------|------|
| `OPENAI_API_KEY` | `LLM_API_KEY` | API 密钥 |
| `LLM_API_BASE` | `LLM_API_BASE` | API 基础 URL |
| `LLM_MODEL_NAME` | `LLM_MODEL_NAME` | 模型名（默认 gpt-4o） |

### 2.2 Qiling Rootfs

下载 Qiling 官方 ARM64 Android rootfs：

```bash
# 方法一：从 qilingframework/rootfs 仓库 sparse clone
mkdir -p rootfs
cd rootfs
git clone --depth=1 --filter=blob:none --sparse https://github.com/qilingframework/rootfs.git ql_rootfs_tmp
cd ql_rootfs_tmp
git sparse-checkout set arm64_android
cp -r arm64_android ../arm64_android
cd ..
rm -rf ql_rootfs_tmp
```

验证目录结构：

```
rootfs/arm64_android/
├── bin/arm64_android_hello
├── proc/self/exe
└── system/
    ├── bin/linker64          # Android 动态链接器
    └── lib64/
        ├── libc.so           # Bionic libc
        └── libdl.so
```

`config/settings.py` 默认路径为 `rootfs/arm64_android`，可通过 `QL_ROOTFS_PATH` 环境变量覆盖。

---

## 3. 构建测试夹具

编译 ARM64 测试 SO 文件（用于单元测试和 Qiling 模拟验证）：

```bash
bash tests/fixtures/build_fixtures.sh
```

该脚本使用 `clang-18 --target=aarch64-linux-gnu` 交叉编译，以 `-nostdlib` 模式构建。`malloc`/`free`/`memcpy` 等符号保持未解析，运行时由 Qiling 的 `DependencyMocker` 拦截并提供模拟实现。

验证构建结果：

```bash
file tests/fixtures/*.so
# 应输出: ELF 64-bit LSB shared object, ARM aarch64
```

5 个测试 SO 文件说明：

| 文件 | 功能 | 漏洞类型 |
|------|------|----------|
| `simple_add.so` | `int add(int, int)` — 无依赖 | 无（基线测试） |
| `jni_test.so` | JNI 风格字节处理函数 | 无 |
| `overflow_test.so` | `vulnerable_copy(buf, len)` — 不检查缓冲区大小 | CWE-122 堆溢出 |
| `uaf_test.so` | `use_after_free(trigger)` — 释放后访问 | CWE-416 |
| `double_free_test.so` | `double_free(trigger)` — 双重释放 | CWE-415 |

---

## 4. 单元测试

```bash
python -m pytest tests/ -v
```

预期结果：**63 个测试全部通过**。

测试覆盖模块：config (7)、apk_io (11)、llm_interface (5)、fuzzing (12)、memory_safety (11)、reporter (7)、pipeline (5)。

---

## 5. Qiling 模拟验证

单独验证 Qiling ARM64 模拟是否正常工作：

```bash
python3 << 'EOF'
from config.settings import load_settings
load_settings()
from src.emulation.qiling_env import EmulatedJNIFunc
import struct

# 测试 simple_add.so — 无 libc 依赖
emu = EmulatedJNIFunc("tests/fixtures/simple_add.so", "add")
emu.initialize()

# 手动设置 C 调用约定 (x0=3, x1=5)，绕过 JNI 约定
ql = emu.ql
ret_addr = ql.mem.map_anywhere(4, info="ret")
ql.mem.write(ret_addr, struct.pack("<I", 0xD65F03C0))  # ARM64 RET
ql.arch.regs.x0 = 3
ql.arch.regs.x1 = 5
ql.arch.regs.x30 = ret_addr
ql.run(begin=emu._func_addr, end=ret_addr, timeout=3000)

result = ql.arch.regs.x0
print(f"add(3, 5) = {result}")  # 预期: 8
emu.destroy()
EOF
```

预期输出：`add(3, 5) = 8`

测试 overflow_test.so（需要 PLT 拦截 mock malloc/free/memcpy）：

```bash
python3 << 'EOF'
from config.settings import load_settings
load_settings()
from src.emulation.qiling_env import EmulatedJNIFunc
import struct

emu = EmulatedJNIFunc("tests/fixtures/overflow_test.so", "vulnerable_copy")
emu.initialize()

ql = emu.ql
input_data = b"A" * 8
input_addr = ql.mem.map_anywhere(len(input_data), info="input")
ql.mem.write(input_addr, input_data)
ret_addr = ql.mem.map_anywhere(4, info="ret")
ql.mem.write(ret_addr, struct.pack("<I", 0xD65F03C0))

ql.arch.regs.x0 = input_addr  # const unsigned char*
ql.arch.regs.x1 = len(input_data)  # int len
ql.arch.regs.x30 = ret_addr
ql.run(begin=emu._func_addr, end=ret_addr, timeout=5000)

print(f"vulnerable_copy returned: {ql.arch.regs.x0}")  # 预期: 65 (ASCII 'A')
emu.destroy()
EOF
```

预期输出：`vulnerable_copy returned: 65`

---

## 6. 完整 Pipeline 运行

### 6.1 准备 APK

将目标 APK 放入 `apk/` 目录：

```bash
ls apk/*.apk
# 例如: com.whatsapp_2.19.230-452939_minAPI15(arm64-v8a)(nodpi)_apkmirror.com.apk
```

### 6.2 Skip-LLM 模式（快速验证）

跳过 LLM 过滤，将所有 JNI 函数视为多媒体函数进行 Fuzz：

```bash
python run_pipeline.py \
    --apk-dir ./apk \
    --output-dir ./output \
    --skip-llm \
    --fuzz-max-runs 10 \
    --fuzz-timeout 30
```

参数说明：

| 参数 | 说明 | 建议值 |
|------|------|--------|
| `--apk-dir` | APK 文件目录 | `./apk` |
| `--output-dir` | 输出目录 | `./output` |
| `--skip-llm` | 跳过 LLM 多媒体过滤 | 开发调试时使用 |
| `--fuzz-max-runs` | 每个函数最大 Fuzz 次数 | 调试: 10; 正式: 100000 |
| `--fuzz-timeout` | 每个函数超时（秒） | 调试: 30; 正式: 300 |
| `--llm-concurrency` | LLM API 并发数 | 4 |
| `--skip-memory-safety` | 跳过内存安全检测 | 不推荐 |

### 6.3 LLM 模式（完整流程）

需确保 `.env` 中的 API 密钥有效：

```bash
python run_pipeline.py \
    --apk-dir ./apk \
    --output-dir ./output \
    --fuzz-max-runs 1000 \
    --fuzz-timeout 120 \
    --llm-concurrency 4
```

LLM 模式会执行三轮自启发式查询：
1. Q1: 该函数是否处理多媒体数据？
2. Q2: 操作类型（解码/编码/转换/其他）
3. Q3: 处理的文件格式（GIF/JPEG/WebP/MP4/未知）

### 6.4 Pipeline 断点续传

Pipeline 支持基于 checkpoint 的断点续传。如果中途中断（Ctrl+C），重新运行相同命令即可从上次进度继续。Checkpoint 文件存储在输出目录：

- `jni_signatures.json` — 提取的 JNI 签名
- `multimedia_functions.json` — LLM 过滤结果
- `fuzz_results/` — 各函数的 Fuzz 结果

### 6.5 输出结构

```
output/
├── logs/pipeline.log              # 完整运行日志
├── jni_signatures.json            # JNI 签名
├── multimedia_functions.json      # LLM 过滤结果
├── llm_audit.jsonl                # LLM API 调用审计日志
├── so_cache/                      # 提取的 SO 文件
│   └── <package>/libxxx.so
├── fuzz_results/                  # 各函数 Fuzz 结果
│   └── <so_name>/<func_name>/
└── reports/
    ├── mediafuzzer_report_<timestamp>.md   # Markdown 报告
    └── mediafuzzer_report_<timestamp>.json # JSON 报告
```

---

## 7. 常见问题排查

### 7.1 `No module named 'pkg_resources'`

**原因**：setuptools ≥82 移除了 `pkg_resources`，而 unicorn/capstone 依赖它。

**修复**：

```bash
pip install "setuptools<71"
```

### 7.2 `Unable to import module .arch.arm64`

**原因**：同 7.1，unicorn 无法导入导致 Qiling 的 ARM64 模块加载失败。

**修复**：同 7.1。

### 7.3 `Symbol 'xxx' not found in xxx.so`

**原因**：Qiling 1.4.6 的 loader 不直接暴露符号表。代码已实现 pyelftools 回退方案。若仍出现此错误，检查 SO 文件是否有 `.dynsym` 段：

```bash
readelf --dyn-syms <so_path> | head
```

### 7.4 `_hook_intr_cb : not handled`

**原因**：Fuzz 目标 SO 调用了未模拟的依赖函数（如 Android 特有的系统调用），Qiling 无法处理。这在真实 APK 的 SO 中常见。

**影响**：会被记录为 `execution_error` 类型的 crash。可通过增强 `DependencyMocker` 添加更多 hook 来缓解。

### 7.5 Harness 编译失败：`undefined symbol: __sancov_lowest_stack`

**原因**：LibFuzzer 的 sanitizer coverage 运行时符号缺失。代码已处理此情况（降级为纯 Python Fuzz 模式）。

**影响**：不影响 Fuzz 执行，只是使用 Strategy A（纯 Python 变异循环）而非 Strategy B（LibFuzzer 主循环）。

### 7.6 交叉编译 `fatal error: 'bits/libc-header-start.h' file not found`

**原因**：系统缺少 ARM64 交叉编译的 libc 头文件。

**修复**：测试 SO 文件已改用 `-nostdlib` + 手动声明，无需 ARM64 libc 头文件。如需编译真实项目的 harness，安装交叉编译工具链：

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu
```

---

## 8. 已知限制

| 限制 | 说明 | 计划 |
|------|------|------|
| 动态 JNI 注册 | 通过 `RegisterNatives` 在 `JNI_OnLoad` 中注册的函数无法静态提取 | M2+ 阶段实现 |
| rootfs 功能有限 | 当前 rootfs 仅含 linker64 + libc.so + libdl.so，缺少 libmedia/libEGL 等 | 可从 `arm64_android6.0` 变体获取更多库 |
| Fuzz 策略 | 仅实现 Strategy A（纯 Python 变异），未使用 LibFuzzer 主循环 | 后续实现 Strategy B/C |
| 并行 Fuzz | Pipeline 串行逐函数 Fuzz，`max_workers` 参数已解析但未使用 | 后续实现 |
| Qiling hook_address 兼容性 | `hook_address` 在 `end=` 模式下可能不触发，改用 `hook_code` 替代 | 已在 DependencyMocker 中修复 |
