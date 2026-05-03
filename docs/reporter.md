# reporter 模块开发文档

## 1. 模块职责

汇总所有模糊测试结果，执行崩溃去重和异常分类，生成结构化的漏洞报告（Markdown 和 JSON 格式）。

## 2. 文件结构

```
src/reporter/
├── __init__.py           # 导出 generate_report, CrashAggregator
├── crash_aggregator.py   # 崩溃去重、异常分类
└── report_generator.py   # 生成最终报告
```

## 3. 详细接口规格

### 3.1 crash_aggregator.py

```python
@dataclass
class UniqueCrash:
    """去重后的崩溃"""
    crash_hash: str           # 崩溃指纹（基于栈回溯哈希）
    input_data_path: str      # 触发崩溃的输入文件路径
    input_data_hex: str       # 触发崩溃的输入数据（hex 编码）
    error_type: str           # 错误类型: crash / uaf / overflow / double_free / tag_mismatch
    error_message: str        # 错误描述
    stack_trace: list[str]    # 栈回溯（如有）
    func_signature: str       # 被测函数签名
    apk_name: str             # 来源 APK
    first_seen: float         # 首次发现时间戳
    occurrence_count: int     # 触发次数
    severity: str             # 严重程度: critical / high / medium / low

class CrashAggregator:
    """
    崩溃去重与分类器。

    去重策略（优先级从高到低）：
    1. 栈回溯哈希：相同调用栈的崩溃视为同一漏洞
    2. 崩溃地址 + 错误类型：相同地址和类型的崩溃视为同一漏洞
    3. 输入数据哈希：相同输入触发视为重复
    """

    def __init__(self):
        self._crashes: dict[str, UniqueCrash] = {}  # crash_hash -> UniqueCrash

    def add_crash(self, crash: dict, func_sig: str, apk_name: str) -> None:
        """
        添加一个崩溃记录。

        Args:
            crash: 来自 FuzzResult 的崩溃字典
            func_sig: 被测函数签名
            apk_name: 来源 APK 名称

        Implementation:
        1. 计算 crash_hash（优先使用栈回溯哈希，否则使用输入数据哈希）
        2. 如果 crash_hash 已存在，增加 occurrence_count
        3. 如果是新崩溃，创建 UniqueCrash 并添加到 _crashes
        4. 根据错误类型推断 severity
        """
        # 计算指纹
        if "stack_trace" in crash and crash["stack_trace"]:
            stack_str = "|".join(crash["stack_trace"])
            crash_hash = hashlib.sha256(stack_str.encode()).hexdigest()[:12]
        else:
            crash_hash = crash.get("crash_hash", "unknown")

        # 严重程度推断
        severity = self._infer_severity(crash)

        if crash_hash in self._crashes:
            self._crashes[crash_hash].occurrence_count += 1
        else:
            self._crashes[crash_hash] = UniqueCrash(
                crash_hash=crash_hash,
                input_data_path=crash.get("input_data_path", ""),
                input_data_hex=crash.get("input_data", ""),
                error_type=crash.get("type", "crash"),
                error_message=crash.get("error_message", crash.get("description", "")),
                stack_trace=crash.get("stack_trace", []),
                func_signature=func_sig,
                apk_name=apk_name,
                first_seen=crash.get("timestamp", time.time()),
                occurrence_count=1,
                severity=severity,
            )

    def _infer_severity(self, crash: dict) -> str:
        """根据错误类型推断严重程度"""
        error_type = crash.get("type", "crash").lower()
        severity_map = {
            "overflow": "critical",
            "uaf": "critical",
            "double_free": "critical",
            "tag_mismatch": "high",
            "crash": "medium",
            "timeout": "low",
        }
        return severity_map.get(error_type, "medium")

    def add_memory_error(self, error: dict, func_sig: str, apk_name: str) -> None:
        """添加内存安全违规（与 add_crash 相同的流程）"""
        self.add_crash(error, func_sig, apk_name)

    def get_all_crashes(self) -> list[UniqueCrash]:
        """获取所有去重后的崩溃，按严重程度排序"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            self._crashes.values(),
            key=lambda c: (severity_order.get(c.severity, 4), -c.occurrence_count),
        )

    def get_summary(self) -> dict:
        """
        获取崩溃统计摘要。

        Returns:
            {
                "total_unique_crashes": int,
                "total_occurrences": int,
                "by_severity": {"critical": N, "high": N, ...},
                "by_type": {"overflow": N, "uaf": N, ...},
                "by_apk": {"com.example.app": N, ...},
            }
        """
        crashes = self.get_all_crashes()
        return {
            "total_unique_crashes": len(crashes),
            "total_occurrences": sum(c.occurrence_count for c in crashes),
            "by_severity": dict(Counter(c.severity for c in crashes)),
            "by_type": dict(Counter(c.error_type for c in crashes)),
            "by_apk": dict(Counter(c.apk_name for c in crashes)),
        }
```

### 3.2 report_generator.py

```python
@dataclass
class ReportConfig:
    """报告生成配置"""
    output_dir: str           # 输出目录
    format: str = "both"      # "markdown" / "json" / "both"
    include_inputs: bool = True  # 是否包含触发输入数据
    max_input_hex_len: int = 256  # 输入数据 hex 最大显示长度
    include_stack_trace: bool = True

class ReportGenerator:
    """生成最终分析报告"""

    def __init__(self, config: ReportConfig | None = None):
        self.config = config or ReportConfig(output_dir=settings.OUTPUT_BASE_DIR)

    def generate(self,
                 fuzz_results: list[FuzzResult],
                 aggregator: CrashAggregator,
                 pipeline_meta: dict) -> str:
        """
        生成完整报告。

        Args:
            fuzz_results: 所有模糊测试结果
            aggregator: 崩溃聚合器
            pipeline_meta: 流水线元信息 {
                "start_time": ...,
                "end_time": ...,
                "total_apks": ...,
                "total_functions": ...,
                "total_multimedia_functions": ...,
                "llm_calls": ...,
                "llm_cost_usd": ...,
            }

        Returns:
            报告文件路径
        """
        os.makedirs(self.config.output_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_name = f"mediafuzzer_report_{timestamp}"

        summary = aggregator.get_summary()

        if self.config.format in ("markdown", "both"):
            md_path = os.path.join(self.config.output_dir, f"{base_name}.md")
            self._generate_markdown(md_path, fuzz_results, aggregator, summary, pipeline_meta)

        if self.config.format in ("json", "both"):
            json_path = os.path.join(self.config.output_dir, f"{base_name}.json")
            self._generate_json(json_path, fuzz_results, aggregator, summary, pipeline_meta)

        return self.config.output_dir

    def _generate_markdown(self, path: str, fuzz_results, aggregator, summary, meta) -> None:
        """生成 Markdown 报告"""
        lines = []

        # 标题
        lines.append("# MediaFuzzer 漏洞分析报告")
        lines.append("")
        lines.append(f"**生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**总运行时间**: {meta['end_time'] - meta['start_time']:.1f} 秒")
        lines.append("")

        # 摘要
        lines.append("## 执行摘要")
        lines.append("")
        lines.append(f"| 指标 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| 分析 APK 数量 | {meta['total_apks']} |")
        lines.append(f"| 提取函数总数 | {meta['total_functions']} |")
        lines.append(f"| 多媒体函数数 | {meta['total_multimedia_functions']} |")
        lines.append(f"| LLM 调用次数 | {meta['llm_calls']} |")
        lines.append(f"| 唯一崩溃数 | {summary['total_unique_crashes']} |")
        lines.append(f"| 崩溃总触发数 | {summary['total_occurrences']} |")
        lines.append("")

        # 崩溃按严重程度
        lines.append("## 崩溃分布")
        lines.append("")
        by_sev = summary.get("by_severity", {})
        for sev in ["critical", "high", "medium", "low"]:
            count = by_sev.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.upper()}**: {count}")
        lines.append("")

        # 详细崩溃列表
        lines.append("## 崩溃详情")
        lines.append("")
        for i, crash in enumerate(aggregator.get_all_crashes(), 1):
            lines.append(f"### 崩溃 #{i}: [{crash.severity.upper()}] {crash.error_type}")
            lines.append("")
            lines.append(f"- **函数**: `{crash.func_signature}`")
            lines.append(f"- **来源 APK**: {crash.apk_name}")
            lines.append(f"- **错误类型**: {crash.error_type}")
            lines.append(f"- **触发次数**: {crash.occurrence_count}")
            lines.append(f"- **描述**: {crash.error_message}")
            if self.config.include_inputs:
                hex_str = crash.input_data_hex[:self.config.max_input_hex_len]
                if len(crash.input_data_hex) > self.config.max_input_hex_len:
                    hex_str += "..."
                lines.append(f"- **触发输入 (hex)**: `{hex_str}`")
            if self.config.include_stack_trace and crash.stack_trace:
                lines.append(f"- **栈回溯**:")
                for frame in crash.stack_trace[:10]:
                    lines.append(f"  - {frame}")
            lines.append("")

        # 覆盖率统计
        lines.append("## 覆盖率统计")
        lines.append("")
        lines.append("| 函数 | 变异轮次 | 覆盖率 | 崩溃数 |")
        lines.append("|------|---------|--------|--------|")
        for result in fuzz_results:
            lines.append(
                f"| `{result.func_sig.native_symbol}` "
                f"| {result.total_runs} "
                f"| {result.coverage_ratio:.2%} "
                f"| {result.unique_crashes} |"
            )
        lines.append("")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _generate_json(self, path: str, fuzz_results, aggregator, summary, meta) -> None:
        """生成 JSON 报告"""
        report = {
            "meta": {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tool": "MediaFuzzer-Replica",
                "version": "0.1.0",
            },
            "pipeline": meta,
            "summary": summary,
            "crashes": [
                {
                    "crash_hash": c.crash_hash,
                    "error_type": c.error_type,
                    "severity": c.severity,
                    "func_signature": c.func_signature,
                    "apk_name": c.apk_name,
                    "error_message": c.error_message,
                    "occurrence_count": c.occurrence_count,
                    "input_data_hex": c.input_data_hex if self.config.include_inputs else None,
                    "stack_trace": c.stack_trace if self.config.include_stack_trace else None,
                    "first_seen": c.first_seen,
                }
                for c in aggregator.get_all_crashes()
            ],
            "fuzz_results": [
                {
                    "func_signature": r.func_sig.native_symbol,
                    "total_runs": r.total_runs,
                    "total_time": r.total_time,
                    "coverage_ratio": r.coverage_ratio,
                    "unique_crashes": r.unique_crashes,
                }
                for r in fuzz_results
            ],
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
```

## 4. 关键实现细节

### 4.1 崩溃去重策略

```
崩溃事件
    │
    ▼
有栈回溯? ──Yes──▶ hash(栈回溯) 作为 crash_hash
    │
    No
    │
    ▼
hash(崩溃地址 + 错误类型) 作为 crash_hash
    │
    ▼
crash_hash 已存在? ──Yes──▶ occurrence_count++
    │
    No
    │
    ▼
创建新 UniqueCrash
```

### 4.2 栈回溯获取

在 Qiling 模拟环境中，可以通过以下方式获取栈回溯：
1. 读取 ARM64 的 FP (X29) 寄存器，遍历栈帧链
2. 使用 `addr2line` 工具将地址转换为源码位置
3. 如果 SO 未剥离调试信息，可以获取函数名和行号

```python
def get_stack_trace(ql: Qiling, so_path: str, max_depth: int = 10) -> list[str]:
    """从 Qiling 状态中提取栈回溯"""
    frames = []
    fp = ql.reg.read(UC_ARM64_REG_X29)
    pc = ql.reg.read(UC_ARM64_REG_PC)

    for _ in range(max_depth):
        if fp == 0:
            break
        frame_str = resolve_address(pc, so_path)
        frames.append(frame_str)
        # 读取上一栈帧
        fp = int.from_bytes(ql.mem.read(fp, 8), "little")
        pc = int.from_bytes(ql.mem.read(fp + 8, 8), "little")

    return frames

def resolve_address(addr: int, so_path: str) -> str:
    """使用 addr2line 解析地址"""
    try:
        result = subprocess.run(
            ["addr2line", "-e", so_path, "-f", "-C", f"{addr:#x}"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return f"{addr:#x}"
```

### 4.3 严重程度分类

| 错误类型 | 严重程度 | 理由 |
|---------|---------|------|
| 堆缓冲区溢出 (overflow) | Critical | 可被利用执行任意代码 |
| 释放后使用 (uaf) | Critical | 可被利用执行任意代码 |
| 双重释放 (double_free) | Critical | 可导致堆元数据损坏 |
| 标签不匹配 (tag_mismatch) | High | 指示指针损坏或UAF |
| 通用崩溃 (crash) | Medium | 可能不可利用 |
| 超时 (timeout) | Low | 可能是拒绝服务 |

## 5. 跨模块依赖

- **依赖**: `fuzzing` (FuzzResult), `memory_safety` (内存违规), `config.settings` (OUTPUT_BASE_DIR)
- **被依赖**: `pipeline` (最终报告生成)

## 6. 错误处理

| 异常场景 | 处理方式 |
|---------|---------|
| 输出目录不存在 | 自动创建 |
| 写入失败 | raise IOError |
| addr2line 不可用 | 使用原始地址 |
| 空崩溃列表 | 生成无崩溃的报告 |

## 7. 实现步骤

1. **Step 1**: 实现 `CrashAggregator` — 去重和分类
2. **Step 2**: 实现 `get_stack_trace()` — 栈回溯提取
3. **Step 3**: 实现 `ReportGenerator._generate_markdown()`
4. **Step 4**: 实现 `ReportGenerator._generate_json()`
5. **Step 5**: 端到端测试：模拟多个 FuzzResult，生成报告

## 8. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| 崩溃去重 | 添加相同 crash_hash 的崩溃 | occurrence_count=2, total_unique=1 |
| 严重程度推断 | 添加 overflow 类型 | severity=critical |
| 多 APK 统计 | 添加来自3个 APK 的崩溃 | by_apk 正确统计 |
| Markdown 生成 | 生成报告 | 文件存在，格式正确 |
| JSON 生成 | 生成报告 | 可被 json.load 解析 |
| 空结果 | 无崩溃 | 报告显示0崩溃 |
| 大量崩溃 | 100个崩溃 | 生成不超时，文件完整 |
