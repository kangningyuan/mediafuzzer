# MediaFuzzer-Replica

复现论文《基于LLM的多媒体原生库模糊测试研究》中的 MediaFuzzer 系统。将自动化 APK 分析、LLM 多媒体函数识别、覆盖率引导灰盒模糊测试与主动内存安全检测相结合，针对 Android 原生库挖掘内存安全漏洞。

**核心流程**：APK 提取 → LLM 筛选多媒体函数 → Qiling 模拟执行 + 格式感知 Fuzz → 内存异常检测 → 漏洞报告

---

## 项目结构

```
MediaFuzzer/
├── config/
│   ├── settings.py                  # 全局配置（路径、LLM、模拟、覆盖率等）
│   └── file_formats/                # 文件格式骨架定义
│       ├── base.py                  #   FormatSkeleton, FieldDef, 格式注册表
│       ├── gif.py                   #   GIF 格式骨架
│       ├── jpeg.py                  #   JPEG 格式骨架
│       └── webp.py                  #   WebP 格式骨架
├── src/
│   ├── apk_io/                      # APK 解包与静态分析
│   │   ├── extractor.py             #   APK 解包、SO 提取、包名识别
│   │   ├── static_analyzer.py       #   DEX native 方法解析、JNI 签名提取
│   │   └── so_loader.py             #   ELF 符号表解析（pyelftools + readelf 回退）
│   ├── llm_interface/               # LLM 多媒体函数筛选
│   │   ├── prompt_templates.py      #   三轮自启发式提示词（Q1:是否多媒体 Q2:操作类型 Q3:文件格式）
│   │   └── querier.py               #   LLMQuerier 客户端，指数退避重试，并发批量过滤
│   ├── emulation/                   # Qiling 模拟执行环境
│   │   ├── qiling_env.py            #   EmulatedJNIFunc（SO 加载、函数调用、JNI 桩、超时）
│   │   ├── dependency_mocker.py     #   文件 I/O、Android log、pthread、网络、libc mem 模拟
│   │   └── hook_manager.py          #   三类钩子管理（coverage / memory_safety / dependency）
│   ├── fuzzing/                     # 模糊测试引擎
│   │   ├── fuzz_worker.py           #   FuzzWorker（纯 Python 变异循环，种子管理，崩溃去重）
│   │   ├── harness.py               #   Harness C 源码生成、Clang 编译、ctypes 桥接
│   │   ├── coverage.py              #   AFL 风格边覆盖率追踪器
│   │   ├── format_aware.py          #   格式感知变异（保持魔数/固定字段不变）
│   │   └── mutator.py               #   自定义变异器 ctypes 桥接
│   ├── memory_safety/               # 内存安全检测
│   │   ├── tag_based.py             #   标记指针检测器、MemoryStateTable（溢出/UAF/双重释放）
│   │   └── sanitizer_hooks.py       #   malloc/calloc/realloc/free + mem_read/mem_write 钩子
│   └── reporter/                    # 结果报告
│       ├── crash_aggregator.py      #   崩溃去重、严重度分类
│       └── report_generator.py      #   Markdown + JSON 报告，栈回溯，addr2line 符号解析
├── tests/                           # 测试（63 个单元测试，全部通过）
│   ├── conftest.py                  #   共享 pytest fixtures
│   ├── test_config.py               #   7 tests
│   ├── test_apk_io.py               #   11 tests
│   ├── test_llm_interface.py        #   5 tests
│   ├── test_fuzzing.py              #   12 tests
│   ├── test_memory_safety.py        #   11 tests
│   ├── test_reporter.py             #   7 tests
│   ├── test_pipeline.py             #   5 tests
│   └── fixtures/                    #   ARM64 测试 SO（5 个漏洞模式 + 构建脚本）
│       ├── build_fixtures.sh
│       ├── simple_add.c / .so       #   基线：int add(int, int)
│       ├── jni_test.c / .so         #   JNI 风格字节处理
│       ├── overflow_test.c / .so    #   CWE-122 堆缓冲区溢出
│       ├── uaf_test.c / .so         #   CWE-416 释放后使用
│       └── double_free_test.c / .so #   CWE-415 双重释放
├── tools/                           # C 辅助工具
│   ├── libfuzzer_harness/           #   LibFuzzer 驱动模板
│   │   ├── harness_template.c       #     LLVMFuzzerTestOneInput + CustomMutator + 共享覆盖率位图
│   │   ├── CMakeLists.txt
│   │   └── build.sh
│   └── coverage_runtime/
│       └── coverage.c               #   AFL 风格边覆盖率运行时
├── rootfs/
│   └── arm64_android/               #   Qiling ARM64 模拟 rootfs（2.3MB）
│       └── system/lib64/{libc.so, libdl.so, linker64}
├── webapp/                          # Web 交互式界面
│   ├── app.py                       #   Flask 应用工厂 + 入口
│   ├── routes.py                    #   HTTP 路由 + JSON API（15 个端点）
│   ├── socket_events.py             #   SocketIO 事件处理
│   ├── pipeline_controller.py       #   管线编排（步骤由用户点击触发）
│   ├── session_state.py             #   会话状态管理
│   ├── llm_adapter.py               #   LLM 适配器（返回全量函数 + 回调）
│   ├── fuzz_monitor.py              #   FuzzWorker 实时状态轮询
│   ├── templates/                   #   Jinja2 模板
│   │   ├── base.html                #     布局：导航栏步骤指示器、CDN
│   │   ├── index.html               #     Step 1: APK 选择
│   │   ├── filtering.html           #     Step 2: LLM 筛选可视化
│   │   ├── emulation.html           #     Step 3: 模拟执行可视化
│   │   ├── fuzzing.html             #     Step 4+5: Fuzz + 内存安全仪表盘
│   │   └── report.html              #     Step 6: 漏洞报告可视化
│   └── static/
│       ├── css/main.css
│       └── js/
│           ├── socket_client.js     #     SocketIO 客户端辅助
│           └── fuzzing_charts.js    #     Chart.js 覆盖率/崩溃图表
├── docs/                            # 模块设计文档（11 篇）
├── run_pipeline.py                  # 主流水线入口（CLI）
├── run_web.sh                       # Web 界面一键启动脚本
├── run_instruction.md               # 详细操作指南
├── requirements.txt
└── .env.example                     # 环境变量模板
```

**代码规模**：~5,400 行（src/ 3,352 + config/ 365 + tests/ 744 + tools/ 229 + webapp/ ~700）

---

## 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux (WSL2 / Ubuntu 22.04+ 已验证) |
| Python | 3.12+ |
| Clang | clang-18 + lld-18（需支持 `--target=aarch64-linux-gnu`） |
| 磁盘空间 | ≥ 500MB |

### 安装

```bash
# 系统依赖
sudo apt-get install -y clang-18 lld-18 binutils-aarch64-linux-gnu

# Python 环境
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# setuptools 必须 <71（unicorn/capstone 依赖 pkg_resources）
pip install "setuptools<71"
```

验证：

```bash
python3 -c "from qiling import Qiling; print('Qiling OK')"
clang-18 --version
```

---

## 配置

### 环境变量

复制模板并填写：

```bash
cp .env.example .env
# 编辑 .env，至少设置 OPENAI_API_KEY
```

| 环境变量 | 对应配置 | 默认值 | 说明 |
|----------|----------|--------|------|
| `OPENAI_API_KEY` | `LLM_API_KEY` | `""` | **必填** — LLM API 密钥 |
| `LLM_API_BASE` | `LLM_API_BASE` | `None` | OpenAI 兼容端点 URL |
| `LLM_MODEL_NAME` | `LLM_MODEL_NAME` | `gpt-4o` | 模型名称 |
| `CLANG_PATH` | `CLANG_PATH` | `/usr/bin/clang-18` | Clang 路径 |
| `QL_ROOTFS_PATH` | `QL_ROOTFS_PATH` | `<项目>/rootfs/arm64_android` | Qiling rootfs 路径 |
| `QL_TIMEOUT` | `QL_TIMEOUT` | `5000` | 模拟超时（ms） |
| `MEM_SAFETY_ENABLED` | `MEM_SAFETY_ENABLED` | `true` | 内存安全检测开关 |
| `OUTPUT_BASE_DIR` | `OUTPUT_BASE_DIR` | `<项目>/output` | 输出目录 |

完整变量列表见 `.env.example`。优先级：**环境变量 > .env 文件 > 代码默认值**。

> **注意**：`LLM_API_KEY` 的环境变量名是 `OPENAI_API_KEY`（兼容 OpenAI SDK 约定）。

---

## 快速开始

### 1. 构建测试夹具

```bash
bash tests/fixtures/build_fixtures.sh
```

### 2. 运行单元测试

```bash
python -m pytest tests/ -v    # 预期: 63 passed
```

### 3. 运行 Pipeline

将目标 APK 放入 `apk/` 目录：

```bash
mkdir -p apk && cp /path/to/target.apk apk/
```

**快速验证（跳过 LLM）**：

```bash
python run_pipeline.py --apk-dir ./apk --output-dir ./output --skip-llm --fuzz-max-runs 10
```

**完整流程（需 API 密钥）**：

```bash
python run_pipeline.py --apk-dir ./apk --output-dir ./output --fuzz-max-runs 1000 --fuzz-timeout 120
```

### CLI 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--apk-dir` | `data/apks` | APK 文件目录 |
| `--output-dir` | `output/<timestamp>` | 输出目录 |
| `--skip-llm` | `False` | 跳过 LLM 过滤，所有函数视为多媒体函数 |
| `--skip-memory-safety` | `False` | 跳过内存安全检测 |
| `--fuzz-max-runs` | `100000` | 每个函数最大 Fuzz 次数 |
| `--fuzz-timeout` | `300` | 每个函数超时（秒） |
| `--llm-concurrency` | `4` | LLM API 并发数 |
| `--max-workers` | `4` | 最大并行 Fuzz 工作数 |

Pipeline 支持**断点续传**：中途中断后重新运行，自动跳过已完成的阶段（基于输出目录中的 checkpoint JSON 文件）。

### 输出结构

```
output/
├── logs/pipeline.log                       # 运行日志
├── jni_signatures.json                     # JNI 签名
├── multimedia_functions.json               # LLM 过滤结果
├── llm_audit.jsonl                         # LLM API 审计日志
├── so_cache/<package>/libxxx.so            # 提取的 SO
├── fuzz_results/<so_name>/<func_name>/     # 各函数 Fuzz 结果
└── reports/
    ├── mediafuzzer_report_<ts>.md          # Markdown 报告
    └── mediafuzzer_report_<ts>.json        # JSON 报告
```

### 4. 运行 Web 界面

除 CLI 模式外，还提供交互式 Web 界面，每个步骤由用户点击触发：

```bash
bash run_web.sh
# 浏览器打开 http://localhost:5000
```

Web 界面功能：

| 步骤 | 页面 | 功能 |
|------|------|------|
| Step 1 | APK 选择 | 列出 `./apk/` 下的 APK，点击选择并提取 |
| Step 2 | LLM 筛选 | 三轮查询实时可视化，展示全部函数（多媒体/非多媒体），用户勾选确认 |
| Step 3 | 模拟执行 | Qiling 初始化日志、已解析符号表 |
| Step 4+5 | Fuzz + 内存安全 | 实时统计（运行次数/覆盖率/崩溃/速度）、Chart.js 图表、内存违规检测 |
| Step 6 | 漏洞报告 | Markdown/JSON/崩溃分页展示，严重度分类，下载报告 |

技术栈：Flask + Flask-SocketIO（threading 模式）、Bootstrap 5.3 + Chart.js 4.x（CDN）、SocketIO 实时推送

---

## 模块设计

### APK I/O (`src/apk_io/`)

- **extractor.py**：解包 APK（zipfile），按 ABI 优先级（arm64-v8a > armeabi-v7a）提取 SO，通过 androguard 或文件名回退获取包名
- **static_analyzer.py**：解析 DEX 中的 `native` 方法声明，匹配 SO 动态符号表中 `Java_` 前缀函数，支持启发式多媒体关键词预过滤
- **so_loader.py**：通过 pyelftools 解析 ELF 符号表和 `.init_array`，readelf 命令行回退

### LLM 接口 (`src/llm_interface/`)

三轮自启发式问询：
1. **Q1**：该函数是否涉及多媒体处理？
2. **Q2**：具体操作类型（解码/编码/渲染/裁剪/其他）？
3. **Q3**：目标文件格式（GIF/JPEG/WebP/MP4/未知）？

`LLMQuerier` 基于 OpenAI SDK，支持指数退避重试、审计日志、`ThreadPoolExecutor` 并发批量过滤。

### 模拟执行 (`src/emulation/`)

- **EmulatedJNIFunc**：加载 SO 到 Qiling，构造伪 JNI 环境（vtable + ARM64 机器码桩），设置寄存器并调用目标函数，支持超时控制
- **DependencyMocker**：模拟 fopen/fread/fwrite/fclose（返回格式特定的种子数据）、Android log（no-op）、pthread（返回成功）、网络（返回 -1）、malloc/free/memcpy/memset（堆分配 + 内存操作）
- **PLT GOT 修补**：扫描 `.rela.plt` 中未解析的 GOT 条目，通过 `hook_code` 拦截 PLT 跳转并执行 Python 钩子后重定向 PC
- **HookManager**：三类钩子注册（coverage / memory_safety / dependency），支持按名称查找

### 模糊测试 (`src/fuzzing/`)

- **FuzzWorker**：Strategy A（纯 Python 变异循环），种子语料管理，MD5 崩溃去重
- **FormatAwareMutator**：7 种变异操作（位翻转/字节插入/删除/替换/交叉/算术/Havoc），保持格式魔数和固定字段不变
- **CoverageTracker**：AFL 风格边覆盖率位图（prev_hash ^ curr_hash），命中率上限 255
- **harness.py**：生成 C 驱动源码 → clang-18 交叉编译 → ctypes 加载 `HarnessBridge`（支持 `__sancov_lowest_stack` 缺失时降级）

### 内存安全 (`src/memory_safety/`)

- **TagBasedDetector**：基于标记指针的主动检测，16-bit tag 编码，MemoryStateTable 追踪分配边界/释放状态，检测溢出/UAF/双重释放/tag 不匹配
- **SanitizerHooks**：安装 Qiling 钩子拦截 malloc/calloc/realloc/free（页对齐分配）和 hook_mem_read/hook_mem_write（访问检查）

### 报告 (`src/reporter/`)

- **CrashAggregator**：三维度去重（栈回溯哈希 / 崩溃地址 / 输入哈希），四级严重度分类（critical/high/medium/low）
- **ReportGenerator**：Markdown + JSON 双格式，FP 链栈回溯，addr2line 符号解析

### Web 界面 (`webapp/`)

- **app.py**：Flask 应用工厂，SocketIO（threading 模式）初始化，存储在 `app.extensions` 供全局访问
- **routes.py**：6 个页面路由 + 15 个 JSON API 端点，所有操作由用户点击触发
- **socket_events.py**：SocketIO 连接管理，共享房间 `mediafuzzer` 广播实时事件
- **pipeline_controller.py**：管线编排核心，通过 `socketio.start_background_task` 在后台线程执行长时任务（APK 提取、LLM 筛选、Fuzzing），实时发射 SocketIO 事件
- **session_state.py**：内存中会话状态容器，单用户模式，`atexit` 清理资源
- **llm_adapter.py**：包装 `LLMQuerier`，返回全部函数（含 `is_multimedia=False`），支持每轮回调（`on_round_start` / `on_function_done`）用于实时可视化
- **fuzz_monitor.py**：独立轮询线程（500ms），读取 `FuzzWorker` 公开属性，发射 `fuzz:stats` / `fuzz:crash` / `memory:violation` / `memory:state` 事件，无需修改 FuzzWorker 内部代码

---

## Qiling 1.4.6 兼容性

本项目针对 Qiling 1.4.6 做了以下适配：

| 问题 | 修复 |
|------|------|
| loader 不暴露 `symbols` / `export_symbols` | `_resolve_via_elf()` 回退：pyelftools 解析 + loader.images[0].base 计算运行时地址 |
| `set_api` 无法拦截未解析的 PLT 调用 | `_patch_plt_got()` 通过 `hook_code` 拦截 PLT 入口 |
| `hook_address` 在 `end=` 模式下不触发 | 改用 `hook_code` 实现 PLT 拦截 |
| unicorn 2.0 依赖 `pkg_resources` | 锁定 `setuptools<71` |

---

## 已知限制

| 限制 | 说明 |
|------|------|
| 动态 JNI 注册 | `RegisterNatives` 在 `JNI_OnLoad` 中注册的函数无法静态提取（M2+ 计划） |
| Fuzz 策略 | 仅实现 Strategy A（纯 Python 变异），Strategy B（LibFuzzer 主循环）待实现 |
| 并行 Fuzz | Pipeline 串行执行，`--max-workers` 参数已解析但未生效 |
| rootfs 功能有限 | 仅含 linker64 + libc.so + libdl.so，如需更多库可换用 `arm64_android6.0` 变体 |

---

## 测试

```bash
# 单元测试（63 个）
python -m pytest tests/ -v

# Qiling 模拟验证
python3 -c "
from config.settings import load_settings; load_settings()
from src.emulation.qiling_env import EmulatedJNIFunc
emu = EmulatedJNIFunc('tests/fixtures/simple_add.so', 'add')
emu.initialize()
import struct
ql = emu.ql; ret = ql.mem.map_anywhere(4, info='ret')
ql.mem.write(ret, struct.pack('<I', 0xD65F03C0))
ql.arch.regs.x0 = 3; ql.arch.regs.x1 = 5; ql.arch.regs.x30 = ret
ql.run(begin=emu._func_addr, end=ret, timeout=3000)
print(f'add(3, 5) = {ql.arch.regs.x0}')  # 预期: 8
emu.destroy()
"
```

详细的测试流程和问题排查见 [run_instruction.md](run_instruction.md)。

---

## 许可证

本项目仅供学术研究使用。确保所有测试的 APK 均在已获授权或研究目的下使用，发现漏洞后请负责任披露。
