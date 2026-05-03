"""Final report generation in Markdown and JSON formats."""

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from src.fuzzing.fuzz_worker import FuzzResult
from src.reporter.crash_aggregator import CrashAggregator, UniqueCrash

logger = logging.getLogger("mediafuzzer.reporter")

_SEVERITY_ICONS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MED", "low": "LOW"}


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    output_dir: str = ""
    format: str = "both"  # "markdown", "json", "both"
    include_inputs: bool = True
    max_input_hex_len: int = 256
    include_stack_trace: bool = True


class ReportGenerator:
    """Generate vulnerability reports from fuzzing results."""

    def __init__(self, config: ReportConfig | None = None) -> None:
        self.config = config or ReportConfig()

    def generate(
        self,
        fuzz_results: list[FuzzResult],
        aggregator: CrashAggregator,
        pipeline_meta: dict | None = None,
    ) -> str:
        """Generate reports. Returns the output directory path."""
        os.makedirs(self.config.output_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        if self.config.format in ("markdown", "both"):
            md_path = os.path.join(
                self.config.output_dir, f"mediafuzzer_report_{timestamp}.md",
            )
            self._generate_markdown(md_path, fuzz_results, aggregator, pipeline_meta)
            logger.info("Markdown report: %s", md_path)

        if self.config.format in ("json", "both"):
            json_path = os.path.join(
                self.config.output_dir, f"mediafuzzer_report_{timestamp}.json",
            )
            self._generate_json(json_path, fuzz_results, aggregator, pipeline_meta)
            logger.info("JSON report: %s", json_path)

        return self.config.output_dir

    def _generate_markdown(
        self,
        path: str,
        fuzz_results: list[FuzzResult],
        aggregator: CrashAggregator,
        pipeline_meta: dict | None,
    ) -> None:
        """Generate Markdown report."""
        summary = aggregator.get_summary()
        crashes = aggregator.get_all_crashes()

        lines: list[str] = []
        lines.append("# MediaFuzzer Vulnerability Report")
        lines.append("")
        lines.append(f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        if pipeline_meta:
            lines.append(f"**APKs processed**: {pipeline_meta.get('apk_count', 'N/A')}")
            lines.append(f"**Functions tested**: {pipeline_meta.get('func_count', 'N/A')}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total unique crashes | {summary['total_unique_crashes']} |")
        lines.append(f"| Total occurrences | {summary['total_occurrences']} |")
        lines.append(f"| Functions fuzzed | {len(fuzz_results)} |")
        for sev, count in sorted(summary.get("by_severity", {}).items()):
            lines.append(f"| {sev.capitalize()} severity | {count} |")
        lines.append("")

        # Crash Distribution
        by_type = summary.get("by_type", {})
        if by_type:
            lines.append("## Crash Distribution by Type")
            lines.append("")
            lines.append("| Error Type | Count |")
            lines.append("|------------|-------|")
            for etype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"| {etype} | {count} |")
            lines.append("")

        # Crash Details
        if crashes:
            lines.append("## Crash Details")
            lines.append("")
            for i, crash in enumerate(crashes, 1):
                lines.append(f"### Crash #{i}: {crash.error_type} [{crash.severity.upper()}]")
                lines.append("")
                lines.append(f"- **Function**: `{crash.func_signature}`")
                lines.append(f"- **APK**: {crash.apk_name or 'N/A'}")
                lines.append(f"- **Error type**: {crash.error_type}")
                lines.append(f"- **Occurrences**: {crash.occurrence_count}")
                if crash.error_message:
                    lines.append(f"- **Message**: {crash.error_message}")
                if self.config.include_inputs and crash.input_data_hex:
                    hex_preview = crash.input_data_hex[:self.config.max_input_hex_len]
                    lines.append(f"- **Input (hex)**: `{hex_preview}`")
                if self.config.include_stack_trace and crash.stack_trace:
                    lines.append(f"- **Stack trace**:")
                    lines.append(f"```")
                    lines.append(crash.stack_trace)
                    lines.append(f"```")
                lines.append("")

        # Coverage Statistics
        if fuzz_results:
            lines.append("## Coverage Statistics")
            lines.append("")
            lines.append("| Function | Runs | Coverage | Crashes | Memory Errors |")
            lines.append("|----------|------|----------|---------|---------------|")
            for fr in fuzz_results:
                lines.append(
                    f"| `{fr.func_sig}` | {fr.total_runs} | "
                    f"{fr.coverage_ratio:.1%} | {len(fr.crashes)} | "
                    f"{len(fr.memory_errors)} |"
                )
            lines.append("")

        with open(path, "w") as f:
            f.write("\n".join(lines))

    def _generate_json(
        self,
        path: str,
        fuzz_results: list[FuzzResult],
        aggregator: CrashAggregator,
        pipeline_meta: dict | None,
    ) -> None:
        """Generate JSON report."""
        summary = aggregator.get_summary()
        crashes = aggregator.get_all_crashes()

        report = {
            "meta": {
                "tool": "MediaFuzzer-Replica",
                "version": "0.1.0",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            "pipeline": pipeline_meta or {},
            "summary": summary,
            "crashes": [
                {
                    "hash": c.crash_hash,
                    "error_type": c.error_type,
                    "severity": c.severity,
                    "func_signature": c.func_signature,
                    "apk_name": c.apk_name,
                    "occurrence_count": c.occurrence_count,
                    "error_message": c.error_message,
                    "input_data_hex": c.input_data_hex if self.config.include_inputs else "",
                    "stack_trace": c.stack_trace if self.config.include_stack_trace else "",
                }
                for c in crashes
            ],
            "fuzz_results": [
                {
                    "func_sig": fr.func_sig,
                    "total_runs": fr.total_runs,
                    "total_time": fr.total_time,
                    "coverage_ratio": fr.coverage_ratio,
                    "unique_crashes": fr.unique_crashes,
                    "memory_errors": len(fr.memory_errors),
                }
                for fr in fuzz_results
            ],
        }

        with open(path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)


def get_stack_trace(ql: Any, so_path: str, max_depth: int = 10) -> str:
    """Walk ARM64 FP (X29) chain and resolve addresses via addr2line."""
    frames: list[str] = []

    try:
        fp = ql.arch.regs.x29
        pc = ql.arch.regs.pc

        # Current frame
        frames.append(resolve_address(pc, so_path))

        # Walk frame pointer chain
        for _ in range(max_depth - 1):
            if fp == 0:
                break
            try:
                data = ql.mem.read(fp, 16)
                import struct
                next_fp = struct.unpack("<Q", data[:8])[0]
                ret_addr = struct.unpack("<Q", data[8:16])[0]
                if ret_addr == 0:
                    break
                frames.append(resolve_address(ret_addr, so_path))
                fp = next_fp
            except Exception:
                break
    except Exception as e:
        logger.warning("Stack trace extraction failed: %s", e)

    return "\n".join(frames)


def resolve_address(addr: int, so_path: str) -> str:
    """Resolve an address using addr2line."""
    try:
        result = subprocess.run(
            ["addr2line", "-e", so_path, "-f", "-C", hex(addr)],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return f"0x{addr:x}: {result.stdout.strip()}"
    except Exception:
        pass
    return f"0x{addr:x}"


def generate_report(
    fuzz_results: list[FuzzResult],
    aggregator: CrashAggregator,
    output_dir: str,
    pipeline_meta: dict | None = None,
) -> str:
    """Convenience function to generate a report."""
    config = ReportConfig(output_dir=output_dir)
    gen = ReportGenerator(config)
    return gen.generate(fuzz_results, aggregator, pipeline_meta)
