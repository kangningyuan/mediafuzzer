---

### 项目名称：MediaFuzzer-Replica

#### 1. 概述
本项目旨在复现论文《基于LLM的多媒体原生库模糊测试研究》中提出的MediaFuzzer系统。系统将自动化的APK分析、基于大语言模型（LLM）的多媒体函数识别与覆盖率引导的灰盒模糊测试相结合，针对原生库中的内存安全漏洞进行高效挖掘。

**核心目标**：
-   从给定的APK集合中自动提取JNI函数签名。
-   利用LLM筛选出潜在的多媒体处理函数。
-   构建全自动的模拟执行模糊测试环境，支持覆盖率反馈、文件格式引导及主动内存异常检测。
-   输出可复现的漏洞报告。

---

#### 2. 环境要求与工具链安装指南

##### 2.1 操作系统与基础依赖

| 组件                | 版本/说明                                                                                                 |
|----------------------|--------------------------------------------------------------------------------------------------------|
| 操作系统            | Ubuntu 22.04+ (推荐)                                                                                      |
| Python               | 3.10+                                                                                                   |
| 二进制模拟框架       | Qiling Framework (基于Unicorn)                                                                           |
| 模糊测试引擎        | LibFuzzer (从LLVM 14+编译)                                                                                |
| 静态分析            | Androguard (用于APK解析), Soot (可选, 用于更精细的Java层分析)                                              |
| LLM API             | OpenAI API (gpt-4o) 或兼容接口，需提供API Key                                                             |
| 其他依赖           | Clang, build-essential, ninja, cmake, addr2line, binutils                                                 |

##### 2.2 编译环境准备

无论最终安装哪些工具，请先确保编译工具链就绪。

```bash
# Ubuntu/Debian 环境
sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build \
  python3 python3-dev python3-pip python3-venv \
  git wget unzip \
  libssl-dev libffi-dev pkg-config \
  binutils addr2line
```

##### 2.3 核心工具安装与验证

**2.3.1 LLVM 与 LibFuzzer (需 v14+ 版本)**

LibFuzzer 自 LLVM 8.0 起已集成在编译器运行时库中，随 Clang 一起分发。为保证与自定义变异器兼容，推荐 LLVM 14+。

**安装**：
```bash
# 方式一：系统包管理（若版本足够）
sudo apt install -y clang-14 libfuzzer-14-dev

# 方式二：官方脚本安装（推荐，版本可控）
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-add-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
sudo apt install -y clang-18 lldb-18 lld-18 libfuzzer-18-dev
```

**验证**：
```bash
clang-18 --version

# 编译一个极简LibFuzzer测试，确认可执行
echo 'int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }' > test_fuzz.c
clang-18 -fsanitize=fuzzer test_fuzz.c -o test_fuzz
./test_fuzz -runs=100  # 若无报错，则安装成功
rm test_fuzz test_fuzz.c
```

**2.3.2 Qiling Framework (基于Unicorn)**

Qiling 是完全的 Python 库，负责二进制模拟执行。它内部集成了 Unicorn 引擎。

**安装**：
```bash
# 推荐在虚拟环境中进行
python3 -m venv mediafuzzer-env
source mediafuzzer-env/bin/activate

pip install wheel
# Qiling 需要特定版本的 Capstone 和 Unicorn
pip install capstone==4.0.2
pip install unicorn==2.0.1.post1
pip install qiling
```

**常见问题与验证**：
```bash
# 验证安装：执行一个示例脚本，模拟简单的ARM64指令
python3 -c "
from qiling import Qiling
from qiling.const import QL_VERBOSE
# 这只会初始化引擎，检查基础库是否就绪
print('Qiling Framework 安装成功')
"
```
**注意**：Qiling 运行目标SO需要完整的根文件系统（rootfs）。你需要在配置中指定rootfs路径（可从 Qiling 官方仓库获取样例 rootfs，或从真实 Android 镜像提取）。

**2.3.3 Androguard (APK 静态分析)**

用于解析 APK 并提取 Java 层 native 方法签名。

**安装**：
```bash
pip install androguard
```

**验证**：
```bash
# 使用 androguard 命令行工具查看任意 APK
androguard decompile -o /tmp/apk_analysis your_test.apk
```

##### 2.4 Python 依赖清单

所有 Python 包集中管理在 `requirements.txt` 中：

```
# 模糊测试与模拟执行核心
qiling>=1.4.5
capstone==4.0.2
unicorn>=2.0.1

# APK静态分析
androguard>=4.1.1

# LLM接口
openai>=1.0.0
httpx

# 工具与数据处理
tqdm
pyyaml
jsonschema
```

安装命令：
```bash
pip install -r requirements.txt
```

##### 2.5 工具链配置文件

安装完成后，在项目 `config/settings.py` 中配置以下关键路径，供所有模块调用：

```python
# config/settings.py

import os

# --- LLVM / LibFuzzer 配置 ---
CLANG_PATH = "/usr/bin/clang-18"
LIBCLANG_RT_PATH = "/usr/lib/llvm-18/lib/clang/18/lib/linux/"

# --- Qiling 模拟环境配置 ---
QL_ROOTFS_PATH = os.path.join(os.path.dirname(__file__), "..", "rootfs", "arm64_android")
QL_ARCH = "arm64"

# --- APK 文件路径 ---
APK_INPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "apks")
SO_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "extracted_so")

# --- LLM 配置 ---
LLM_MODEL_NAME = "gpt-4o"
LLM_API_KEY = os.getenv("OPENAI_API_KEY")  # 密钥从环境变量读取，切勿硬编码
LLM_MAX_RETRIES = 3

# ... 其他配置如覆盖率位图大小、内存异常检测开关等
```

---

#### 3. 项目文件结构

```
MediaFuzzer/
├── config/
│   ├── __init__.py
│   ├── settings.py               # 全局配置：LLM API密钥、并发数、变异策略等
│   └── file_formats/             # 文件格式骨架定义
│       ├── gif.py
│       ├── jpeg.py
│       ├── webp.py
│       └── ...
├── src/
│   ├── __init__.py
│   ├── apk_io/                    # APK输入输出处理模块
│   │   ├── __init__.py
│   │   ├── extractor.py           # APK解包、SO库提取
│   │   ├── static_analyzer.py     # 提取JNI函数签名
│   │   └── so_loader.py           # 辅助：解析ELF符号表
│   ├── llm_interface/             # LLM交互模块
│   │   ├── __init__.py
│   │   ├── prompt_templates.py    # 自启发式提示词模板
│   │   └── querier.py             # 调用LLM API进行筛选与解析
│   ├── emulation/                 # 模拟执行环境
│   │   ├── __init__.py
│   │   ├── qiling_env.py          # Qiling环境初始化、JNI桩实现
│   │   ├── dependency_mocker.py   # 系统调用、文件操作模拟
│   │   └── hook_manager.py        # 统一插桩管理
│   ├── fuzzing/                   # 模糊测试引擎
│   │   ├── __init__.py
│   │   ├── harness.py             # LibFuzzer测试驱动生成
│   │   ├── coverage.py            # 基本块覆盖率收集
│   │   ├── format_aware.py        # 文件格式感知变异
│   │   ├── mutator.py             # 自定义突变策略
│   │   └── fuzz_worker.py         # 单个函数的模糊测试任务控制
│   ├── memory_safety/             # 内存安全检测
│   │   ├── __init__.py
│   │   ├── tag_based.py           # 基于标记指针的主动检测（影子内存/内存状态表）
│   │   └── sanitizer_hooks.py     # 挂钩分配/释放/内存访问函数
│   └── reporter/                  # 结果报告
│       ├── __init__.py
│       ├── crash_aggregator.py    # 崩溃去重、异常收集
│       └── report_generator.py    # 生成最终Markdown/JSON报告
├── tests/                         # 单元测试与模块集成测试
│   ├── test_apk_io.py
│   ├── test_llm_interface.py
│   ├── test_emulation.py
│   ├── test_fuzzing.py
│   ├── test_memory_safety.py
│   └── fixtures/                  # 测试用极简APK、SO样例
│       └── ...
├── tools/                         # C/C++辅助工具
│   ├── libfuzzer_harness/         # LibFuzzer驱动的C模板及编译脚本
│   │   ├── harness_template.c
│   │   ├── CMakeLists.txt
│   │   └── build.sh
│   └── coverage_runtime/          # 覆盖率插桩运行时（如Qiling钩子优化版）
│       └── coverage.c
├── run_pipeline.py                # 主流水线脚本：串联所有模块
├── requirements.txt               # Python依赖列表
└── README.md                      # 本开发文档
```

---

#### 4. 模块详细设计与开发流程

##### 4.1 APK I/O 模块

**职责**：接收APK路径列表，输出每个APK内所有JNI函数的签名信息（包括Java层声明和Native层对应函数名）。

**核心类/函数**：
-   `extract_so_files(apk_path) -> List[str]`：解包APK，提取全部 `.so` 文件。
-   `parse_jni_bindings(so_path, dex_path) -> List[dict]`：分析静态JNI绑定。通过 `Androguard` 分析 `classes.dex` 找出 `native` 方法，同时在SO的动态符号表中匹配 `Java_` 前缀的函数。返回结构如：`{"java_full_sig": "com.example.MediaProcessor.decode(Ljava/lang/String;)[B", "native_symbol": "Java_com_example_MediaProcessor_decode", "params": [...], "ret": "[B"}`。

**测试流程**：
1.  使用 `tests/fixtures/` 下的最小化APK（手动编写一个简单JNI调用）进行单元测试，确认能够精准提取出所有已知签名。
2.  对真实APK（如微信）进行测试，检查输出签名的完整性和格式正确性。

##### 4.2 LLM接口模块

**职责**：基于JNI签名，利用自启发式问询判断函数是否处理多媒体任务，并识别操作类型和文件格式。

**核心设计**：
-   `prompt_templates.py` 中封装论文图2的对话逻辑：
    1.  **Q1**: "Analyze the following function signature and determine if it involves multimedia processing (e.g., image, video, audio codec, editing, conversion). Answer 'Yes' or 'No' only. Signature: {signature}"
    2.  **Q2**: (if Yes) "What specific multimedia operation does this function perform? (e.g., decoding, encoding, rendering, clipping)."
    3.  **Q3**: (if Yes) "What target file format does this function process? (e.g., GIF, JPEG, unknown)."
-   `querier.py` 需处理API调用、重试、结果解析，并以结构化数组返回筛选出的函数列表，附带上识别的操作类型和格式。

**测试流程**：
1.  使用论文表3中提供的人工标注数据集（需要预先准备含少量明确多媒体函数的APK），验证LLM筛选的召回率和精确率是否达标。
2.  单独调试提示词，确保返回格式稳定，可解析。

##### 4.3 模拟执行环境模块

**职责**：为单个原生函数提供可运行的虚拟环境，包括JNI调用桩、系统调用模拟、内存管理钩子。采用Qiling Framework作为基础。

**核心实现**：
-   `qiling_env.py` 中定义 `EmulatedJNIFunc` 类，该类加载指定SO，初始化Qiling引擎，并设置FS、根目录等。
-   `dependency_mocker.py`：编写针对 `fopen`、`fread`、`fwrite`、`malloc`、`free` 等函数的Qiling钩子。对于文件操作，如果访问路径不存在，返回伪造的文件描述符并提供控制的数据内容。
-   `hook_manager.py` 负责管理和解注册所有钩子，方便后续模糊测试引擎调用。

**测试流程**：
1.  手动编译一个极简的“测试桩”so（如实现一个函数 `int add(int a, int b)` ），验证Qiling能够成功加载、调用该函数并返回正确结果。
2.  编写一个模拟了JNI调用的so，测试 `FindClass`、`NewStringUTF` 等桩实现是否正确，确保不因JNI崩溃而中止。
3.  测试文件系统模拟：让目标函数尝试打开一个已知路径的文件，返回我们预置的内存映射内容。

##### 4.4 模糊测试引擎模块

**职责**：将LibFuzzer与Qiling深度集成，实现覆盖率引导和格式感知的变异。

**核心组件**：
-   **Harness编译** (`harness.py` + `libfuzzer_harness/`)：
    -   `harness_template.c` 是一个C语言测试驱动，其 `LLVMFuzzerTestOneInput` 函数通过预定义的接口调用Python回调，将变异数据传递给Qiling中的目标函数。
    -   编译为共享库 `libfuzzer_harness.so`，由Python通过 `ctypes` 加载并启动LibFuzzer循环。
-   **覆盖率引导** (`coverage.py`)：
    -   在Qiling代码执行钩子中，于每个基本块的入口处调用回调，计算当前地址的哈希并更新全局覆盖率位图。
    -   每轮模糊测试结束，将位图反馈给LibFuzzer（通过 `__sanitizer_cov_trace_pc` 等内置函数或自定义 `__libfuzzer_extra_counters`）。
-   **格式感知** (`format_aware.py`)：
    -   根据LLM识别的文件格式，加载 `config/file_formats/` 下对应的骨架定义（例如GIF：固定文件头、逻辑屏幕描述符、图像数据块结构）。
    -   在LibFuzzer的 `LLVMFuzzerCustomMutator` 中实现变异策略，保持特定字段（如魔数字、校验和）不变，只对数据内容进行变异。

**测试流程**：
1.  先不接入Qiling，使用一个纯C函数作为被测目标，验证LibFuzzer harness能够正确变异和反馈覆盖率。
2.  将Harness与Qiling集成，测试对简单函数（如解析一个固定字节串）的模糊测试，确认覆盖率位图能正常收集。
3.  测试格式感知变异：输入一个带GIF头的种子，检查变异后样本的文件头是否未被破坏。

##### 4.5 内存安全检测模块

**职责**：实现基于标记指针的主动内存异常检测（时间换空间策略），替代依赖进程崩溃的被动检测。

**设计要点** (参考论文2.4节)：
-   维护一个全局内存状态表，记录每块已分配内存的边界、释放状态以及一个随机分配的标签（tag）。
-   指针的高16位编码该标签（模拟执行环境可自定义TBI效果）。所有内存分配函数（`malloc`, `calloc`, `realloc`）入口处，为新分配的内存生成标签并写入状态表，标签也编码到返回的指针中。
-   在Qiling的 `hook_mem_read`/`hook_mem_write` 中，读取指针标签，并与状态表中目标内存块的标签比较，若不符或内存已释放，立即报告异常。
-   内存释放函数入口处检查双重释放、释放状态一致性。

**测试流程**：
1.  使用标准漏洞测试集 **Juliet C/C++** 编译出包含CWE122, 415, 416漏洞的SO。
2.  单独运行内存检测模块，对比被动崩溃检测和我们主动检测的检出数量，确保与论文图6结果相符。
3.  测试性能开销，确保在模拟环境下内存消耗可控（<2倍原内存占用）。

---

#### 5. 集成流程与主流水线

`run_pipeline.py` 需实现如下自动流程：

1.  **初始化**：加载配置文件，初始化LLM连接，准备输出目录。
2.  **APK预处理**：遍历输入目录，调用 `apk_io` 提取所有JNI签名。
3.  **LLM筛选**：批量调用 `llm_interface`，生成多媒体函数清单，按操作类型和格式分类。
4.  **模糊测试调度**：为清单中每个函数创建独立任务，任务内部：
    -   初始化模拟环境，注入覆盖率、内存安全钩子。
    -   生成种子（依据识别的格式）。
    -   启动LibFuzzer harness，监控运行（时间/轮次）。
    -   实时收集崩溃和内存异常报告，写入对应日志。
5.  **报告生成**：所有任务结束后，调用 `reporter` 模块汇总去重，输出最终分析报告（漏洞函数、触发条件、堆栈信息）。

---

#### 6. 开发顺序与里程碑

| 阶段 | 主要任务                                       | 完成标准                                                     |
|------|----------------------------------------------|------------------------------------------------------------|
| M1   | 项目骨架搭建，APK I/O模块开发与测试            | 能正确提取100个真实APK的所有JNI签名                         |
| M2   | LLM接口模块开发，调通多轮对话并验证筛选效果      | 对标注数据集筛选召回率 > 90%                                 |
| M3   | 模拟环境搭建，完成JNI桩、系统调用模拟、覆盖率插桩 | 极简SO（含JNI调用）能稳定运行1000轮模糊测试而不崩溃            |
| M4   | 模糊测试引擎集成，覆盖率反馈与格式感知实现       | 对已知漏洞的WhatsApp SO可触发CVE-2019-11932                 |
| M5   | 内存安全检测模块开发，验证对Juliet测试集的检出率   | 对CWE122/415/416的检出数量不低于论文报告数据                 |
| M6   | 全流程串联，运行大规模APK测试，生成报告           | 在500个APK上稳定运行并输出结果报告，复现至少一个零日漏洞（或已知漏洞）|

---

#### 7. 注意事项

-   **版权与合法合规**：确保所有测试的APK均在已获得授权或研究目的下使用，复现漏洞后及时负责任的披露。
-   **资源消耗**：大规模模糊测试极度消耗CPU和内存，建议在高性能服务器上运行，利用多进程并行。
-   **可重现性**：所有随机种子、LLM调用记录、变异样本均需保存至 `output/<timestamp>/` 目录，便于回溯分析。

---