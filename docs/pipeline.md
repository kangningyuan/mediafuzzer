# run_pipeline 主流水线开发文档

## 1. 模块职责

串联所有模块，实现从 APK 输入到漏洞报告输出的全自动流程。

## 2. 文件位置

```
run_pipeline.py    # 主流水线脚本
```

## 3. 流水线架构

```
┌────────────────────────────────────────────────────────────────┐
│                     run_pipeline.py                            │
│                                                                │
│  1. 初始化                                                      │
│     ├─ 加载配置                                                 │
│     ├─ 初始化 LLM 连接                                          │
│     └─ 准备输出目录                                              │
│                                                                │
│  2. APK 预处理                                                  │
│     ├─ 遍历 APK_INPUT_DIR                                      │
│     ├─ extract_so_files() → 提取 .so                            │
│     └─ parse_jni_bindings() → 提取 JNI 签名                     │
│                                                                │
│  3. LLM 筛选                                                    │
│     └─ filter_multimedia_functions() → 多媒体函数清单             │
│                                                                │
│  4. 模糊测试调度                                                 │
│     ├─ 对每个多媒体函数创建 FuzzWorker                             │
│     ├─ 初始化 EmulatedJNIFunc + CoverageTracker                 │
│     ├─ 初始化 MemorySafetyChecker                               │
│     ├─ 生成种子 → 启动模糊测试                                     │
│     ├─ 实时收集崩溃和内存异常                                      │
│     └─ 支持多进程并行                                             │
│                                                                │
│  5. 报告生成                                                    │
│     ├─ CrashAggregator 汇总去重                                  │
│     └─ ReportGenerator 生成报告                                  │
└────────────────────────────────────────────────────────────────┘
```

## 4. 详细接口规格

```python
@dataclass
class PipelineConfig:
    """流水线配置"""
    apk_dir: str                # APK 输入目录
    output_dir: str             # 输出目录
    max_workers: int = 4        # 并行模糊测试 worker 数
    fuzz_timeout: int = 300     # 单函数模糊测试超时（秒）
    fuzz_max_runs: int = 100000 # 单函数最大变异轮次
    llm_concurrency: int = 4    # LLM 并发数
    skip_llm: bool = False      # 跳过 LLM 筛选（用于调试）
    skip_memory_safety: bool = False  # 跳过内存安全检测

def run_pipeline(config: PipelineConfig) -> str:
    """
    执行完整流水线。

    Args:
        config: 流水线配置

    Returns:
        报告输出目录路径

    Raises:
        RuntimeError: 关键步骤失败
    """
    pipeline_meta = {
        "start_time": time.time(),
        "total_apks": 0,
        "total_functions": 0,
        "total_multimedia_functions": 0,
        "llm_calls": 0,
        "llm_cost_usd": 0.0,
    }

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(config.output_dir, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    # 设置日志
    setup_logging(output_dir)

    logging.info("=" * 60)
    logging.info("MediaFuzzer Pipeline Starting")
    logging.info(f"Output: {output_dir}")
    logging.info("=" * 60)

    # ===== Step 1: APK 预处理 =====
    logging.info("[Step 1/5] APK Preprocessing")

    apk_files = list_apk_files(config.apk_dir)
    pipeline_meta["total_apks"] = len(apk_files)
    logging.info(f"Found {len(apk_files)} APK files")

    all_signatures = {}
    for apk_path in tqdm(apk_files, desc="Extracting JNI signatures"):
        try:
            sigs = extract_so_files(apk_path, os.path.join(output_dir, "so_cache"))
            jni_sigs = []
            for so_path in sigs:
                jni_sigs.extend(parse_jni_bindings(so_path, apk_path))
            all_signatures[apk_path] = jni_sigs
            pipeline_meta["total_functions"] += len(jni_sigs)
        except Exception as e:
            logging.error(f"Failed to process {apk_path}: {e}")

    logging.info(f"Total JNI signatures extracted: {pipeline_meta['total_functions']}")

    # 保存签名到中间文件
    sig_output_path = os.path.join(output_dir, "jni_signatures.json")
    save_signatures(all_signatures, sig_output_path)

    # ===== Step 2: LLM 筛选 =====
    logging.info("[Step 2/5] LLM Multimedia Function Filtering")

    all_signatures_flat = []
    for apk_path, sigs in all_signatures.items():
        all_signatures_flat.extend(sigs)

    if config.skip_llm:
        # 调试模式：将所有函数视为多媒体函数
        multimedia_funcs = [
            MultimediaFuncInfo(
                jni_signature=sig,
                is_multimedia=True,
                operation_type="unknown",
                file_format="unknown",
                confidence=0.5,
                raw_responses=["skipped"],
            )
            for sig in all_signatures_flat
        ]
    else:
        multimedia_funcs = filter_multimedia_functions(
            all_signatures_flat,
            concurrency=config.llm_concurrency,
        )

    pipeline_meta["total_multimedia_functions"] = len(multimedia_funcs)
    logging.info(f"Multimedia functions identified: {len(multimedia_funcs)}")

    # 保存筛选结果
    mm_output_path = os.path.join(output_dir, "multimedia_functions.json")
    save_multimedia_funcs(multimedia_funcs, mm_output_path)

    # ===== Step 3: 模糊测试调度 =====
    logging.info("[Step 3/5] Fuzzing Scheduling")

    fuzz_results = []
    aggregator = CrashAggregator()

    # 按文件格式分组（相同格式的函数共享种子）
    format_groups: dict[str, list[MultimediaFuncInfo]] = {}
    for func in multimedia_funcs:
        fmt = func.file_format
        format_groups.setdefault(fmt, []).append(func)

    # 使用进程池并行执行模糊测试
    fuzz_tasks = []
    for func_info in multimedia_funcs:
        apk_name = os.path.basename(func_info.jni_signature.so_path)
        func_output_dir = os.path.join(
            output_dir, "fuzz_results",
            apk_name,
            func_info.jni_signature.native_symbol,
        )
        fuzz_tasks.append((func_info, func_output_dir, config))

    # 串行执行（M4 阶段可改为并行）
    for i, (func_info, func_output_dir, cfg) in enumerate(
        tqdm(fuzz_tasks, desc="Fuzzing functions")
    ):
        logging.info(
            f"[{i+1}/{len(fuzz_tasks)}] Fuzzing: "
            f"{func_info.jni_signature.native_symbol}"
        )
        try:
            result = fuzz_single_function(func_info, func_output_dir, cfg)
            fuzz_results.append(result)

            # 实时收集崩溃
            for crash in result.crashes:
                apk_name = os.path.basename(func_info.jni_signature.so_path)
                aggregator.add_crash(crash, func_info.jni_signature.java_full_sig, apk_name)
            for error in result.memory_errors:
                apk_name = os.path.basename(func_info.jni_signature.so_path)
                aggregator.add_memory_error(error, func_info.jni_signature.java_full_sig, apk_name)

        except Exception as e:
            logging.error(f"Fuzzing failed for {func_info.jni_signature.native_symbol}: {e}")

    # ===== Step 4: 内存安全结果汇总 =====
    logging.info("[Step 4/5] Memory Safety Results Aggregation")
    # 内存安全违规已在 Step 3 中实时收集

    # ===== Step 5: 报告生成 =====
    logging.info("[Step 5/5] Report Generation")

    pipeline_meta["end_time"] = time.time()

    report_config = ReportConfig(output_dir=os.path.join(output_dir, "reports"))
    report_gen = ReportGenerator(report_config)
    report_path = report_gen.generate(fuzz_results, aggregator, pipeline_meta)

    logging.info("=" * 60)
    logging.info(f"Pipeline Complete")
    logging.info(f"Total time: {pipeline_meta['end_time'] - pipeline_meta['start_time']:.1f}s")
    logging.info(f"Unique crashes: {aggregator.get_summary()['total_unique_crashes']}")
    logging.info(f"Report: {report_path}")
    logging.info("=" * 60)

    return output_dir


def fuzz_single_function(
    func_info: MultimediaFuncInfo,
    output_dir: str,
    config: PipelineConfig,
) -> FuzzResult:
    """
    对单个函数执行完整模糊测试。

    Steps:
    1. 创建 EmulatedJNIFunc 并初始化
    2. 创建 CoverageTracker 并注册
    3. 创建 TagBasedDetector 和 SanitizerHooks（如果启用）
    4. 创建 FormatAwareMutator
    5. 创建 FuzzWorker 并运行
    6. 收集结果并清理
    """
    # 初始化模拟环境
    emulated_func = EmulatedJNIFunc(
        so_path=func_info.jni_signature.so_path,
        func_symbol=func_info.jni_signature.native_symbol,
    )
    emulated_func.initialize()

    # 覆盖率追踪
    cov_tracker = CoverageTracker()
    cov_tracker.register_hooks(emulated_func)

    # 内存安全检测
    memory_violations = []
    if not config.skip_memory_safety and settings.MEM_SAFETY_ENABLED:
        detector = TagBasedDetector(emulated_func.ql, emulated_func.hook_mgr)
        sanitizer = SanitizerHooks(emulated_func.ql, detector, emulated_func.hook_mgr)
        sanitizer.install()

    # 格式感知变异器
    format_mutator = FormatAwareMutator(
        format_name=func_info.file_format if func_info.file_format != "UNKNOWN" else None
    )

    # 创建并运行 FuzzWorker
    worker = FuzzWorker(func_info, output_dir)
    worker.emulated_func = emulated_func
    worker.cov_tracker = cov_tracker
    worker.format_mutator = format_mutator

    result = worker.run(
        max_runs=config.fuzz_max_runs,
        timeout=config.fuzz_timeout,
    )

    # 附加内存违规（如果有）
    if not config.skip_memory_safety and settings.MEM_SAFETY_ENABLED:
        result.memory_errors = detector.get_violations()

    # 清理
    worker.teardown()

    return result


def list_apk_files(apk_dir: str) -> list[str]:
    """列出目录下所有 APK 文件"""
    apk_files = []
    for root, dirs, files in os.walk(apk_dir):
        for f in files:
            if f.endswith(".apk"):
                apk_files.append(os.path.join(root, f))
    return sorted(apk_files)


def setup_logging(output_dir: str) -> None:
    """配置日志：同时输出到控制台和文件"""
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # 控制台
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(log_format))

    # 文件
    file_handler = logging.FileHandler(
        os.path.join(log_dir, "pipeline.log"), encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(log_format))

    # 根 logger
    root_logger = logging.getLogger("mediafuzzer")
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def save_signatures(signatures: dict, path: str) -> None:
    """保存 JNI 签名到 JSON"""
    data = {}
    for apk_path, sigs in signatures.items():
        data[apk_path] = [
            {
                "java_full_sig": s.java_full_sig,
                "native_symbol": s.native_symbol,
                "class_name": s.class_name,
                "method_name": s.method_name,
                "return_type": s.return_type,
                "so_path": s.so_path,
            }
            for s in sigs
        ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_multimedia_funcs(funcs: list[MultimediaFuncInfo], path: str) -> None:
    """保存多媒体函数筛选结果到 JSON"""
    data = [
        {
            "java_full_sig": f.jni_signature.java_full_sig,
            "native_symbol": f.jni_signature.native_symbol,
            "operation_type": f.operation_type,
            "file_format": f.file_format,
            "confidence": f.confidence,
        }
        for f in funcs
    ]
    with open(path, "w", encoding="utf-8") as f_out:
        json.dump(data, f_out, indent=2, ensure_ascii=False)
```

## 5. 命令行接口

```python
def main():
    parser = argparse.ArgumentParser(description="MediaFuzzer Pipeline")
    parser.add_argument("--apk-dir", default=settings.APK_INPUT_DIR,
                        help="APK input directory")
    parser.add_argument("--output-dir", default=settings.OUTPUT_BASE_DIR,
                        help="Output directory")
    parser.add_argument("--max-workers", type=int, default=4,
                        help="Parallel fuzz workers")
    parser.add_argument("--fuzz-timeout", type=int, default=300,
                        help="Per-function fuzzing timeout (seconds)")
    parser.add_argument("--fuzz-max-runs", type=int, default=100000,
                        help="Per-function max mutation rounds")
    parser.add_argument("--llm-concurrency", type=int, default=4,
                        help="LLM API concurrency")
    parser.add_argument("--skip-llm", action="store_true",
                        help="Skip LLM filtering (debug mode)")
    parser.add_argument("--skip-memory-safety", action="store_true",
                        help="Skip memory safety detection")
    args = parser.parse_args()

    config = PipelineConfig(
        apk_dir=args.apk_dir,
        output_dir=args.output_dir,
        max_workers=args.max_workers,
        fuzz_timeout=args.fuzz_timeout,
        fuzz_max_runs=args.fuzz_max_runs,
        llm_concurrency=args.llm_concurrency,
        skip_llm=args.skip_llm,
        skip_memory_safety=args.skip_memory_safety,
    )

    output_dir = run_pipeline(config)
    print(f"\nResults: {output_dir}")

if __name__ == "__main__":
    main()
```

## 6. 输出目录结构

```
output/
└── 20260504_103000/              # 时间戳目录
    ├── logs/
    │   └── pipeline.log          # 运行日志
    ├── so_cache/                 # 提取的 SO 缓存
    │   └── com.example.app/
    │       └── lib/
    │           └── arm64-v8a/
    │               └── libnative.so
    ├── jni_signatures.json       # JNI 签名中间结果
    ├── multimedia_functions.json # LLM 筛选结果
    ├── llm_audit.jsonl           # LLM 调用审计日志
    ├── fuzz_results/             # 各函数的模糊测试结果
    │   └── libnative.so/
    │       └── Java_com_example_Foo_bar/
    │           ├── seeds/        # 种子语料
    │           ├── crashes/      # 崩溃输入
    │           └── fuzz_log.txt  # 单函数运行日志
    └── reports/                  # 最终报告
        ├── mediafuzzer_report_20260504_103000.md
        └── mediafuzzer_report_20260504_103000.json
```

## 7. 关键实现细节

### 7.1 断点续传

流水线应支持从断点续传：
1. 检查 `output/<timestamp>/` 是否存在
2. 检查 `jni_signatures.json` 是否已存在，跳过 APK 预处理
3. 检查 `multimedia_functions.json` 是否已存在，跳过 LLM 筛选
4. 检查 `fuzz_results/` 下哪些函数已完成，跳过已完成的

```python
def load_checkpoint(output_dir: str) -> dict | None:
    """加载检查点"""
    checkpoint_path = os.path.join(output_dir, "checkpoint.json")
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as f:
            return json.load(f)
    return None

def save_checkpoint(output_dir: str, state: dict) -> None:
    """保存检查点"""
    checkpoint_path = os.path.join(output_dir, "checkpoint.json")
    with open(checkpoint_path, "w") as f:
        json.dump(state, f, indent=2)
```

### 7.2 资源管理

- 每个 FuzzWorker 完成后立即清理 Qiling 引擎
- 限制并行 worker 数防止内存溢出
- 监控系统内存使用，超过阈值时暂停调度

### 7.3 信号处理

```python
import signal

def handle_sigint(signum, frame):
    """优雅退出：保存检查点后退出"""
    logging.info("Received SIGINT, saving checkpoint...")
    # 保存当前状态
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)
```

## 8. 跨模块依赖

- **依赖**: 所有模块 (config, apk_io, llm_interface, emulation, fuzzing, memory_safety, reporter)
- **被依赖**: 无（顶层入口）

## 9. 错误处理

| 异常场景 | 处理方式 |
|---------|---------|
| APK 目录为空 | warning，继续执行（无函数可测试） |
| 单个 APK 处理失败 | 记录错误，继续处理其他 APK |
| LLM API 不可用 | 如果 skip_llm=True 继续执行，否则 raise |
| 单个函数模糊测试失败 | 记录错误，继续测试其他函数 |
| 输出目录不可写 | raise |
| 磁盘空间不足 | warning 并尝试继续 |

## 10. 实现步骤

1. **Step 1**: 实现 `PipelineConfig` 和命令行解析
2. **Step 2**: 实现 `setup_logging()`
3. **Step 3**: 实现 APK 预处理阶段
4. **Step 4**: 实现 LLM 筛选阶段
5. **Step 5**: 实现 `fuzz_single_function()`
6. **Step 6**: 实现模糊测试调度循环
7. **Step 7**: 实现报告生成阶段
8. **Step 8**: 实现断点续传
9. **Step 9**: 实现信号处理和优雅退出
10. **Step 10**: 端到端测试

## 11. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| 空目录 | APK 目录为空 | 不崩溃，报告显示0函数 |
| 单 APK | 含1个 APK | 完整执行，报告生成 |
| skip_llm 模式 | --skip-llm | 跳过 LLM，所有函数进入模糊测试 |
| 断点续传 | 中断后重新运行 | 跳过已完成步骤 |
| 信号处理 | 运行中 Ctrl+C | 保存检查点后退出 |
| 资源清理 | 运行完成后 | 无残留进程，Qiling 引擎已销毁 |
| 日志记录 | 检查日志文件 | 所有阶段有日志记录 |
| 输出完整性 | 检查输出目录 | 所有预期文件存在 |
