"""Tests for reporter module."""

import json
import os
import tempfile

import pytest

from src.reporter.crash_aggregator import CrashAggregator, UniqueCrash, _infer_severity
from src.reporter.report_generator import ReportGenerator, ReportConfig
from src.fuzzing.fuzz_worker import FuzzResult


class TestCrashAggregator:
    """Test crash deduplication and classification."""

    def test_add_crash_deduplicates(self):
        """Same crash hash deduplicates and increments count."""
        agg = CrashAggregator()
        crash1 = {"error_type": "crash", "stack_trace": "frame1\nframe2"}
        crash2 = {"error_type": "crash", "stack_trace": "frame1\nframe2"}
        agg.add_crash(crash1, func_sig="test_func", apk_name="test.apk")
        agg.add_crash(crash2, func_sig="test_func", apk_name="test.apk")
        crashes = agg.get_all_crashes()
        assert len(crashes) == 1
        assert crashes[0].occurrence_count == 2

    def test_severity_inference(self):
        """Severity is correctly inferred from error type."""
        assert _infer_severity("overflow") == "critical"
        assert _infer_severity("uaf") == "critical"
        assert _infer_severity("double_free") == "critical"
        assert _infer_severity("tag_mismatch") == "high"
        assert _infer_severity("crash") == "medium"
        assert _infer_severity("timeout") == "low"

    def test_summary_statistics(self):
        """Summary returns correct statistics."""
        agg = CrashAggregator()
        agg.add_crash({"error_type": "overflow", "stack_trace": "frame_a"}, func_sig="f1", apk_name="a.apk")
        agg.add_crash({"error_type": "uaf", "stack_trace": "frame_b"}, func_sig="f2", apk_name="b.apk")
        agg.add_crash({"error_type": "crash", "stack_trace": "frame_c"}, func_sig="f3", apk_name="a.apk")
        summary = agg.get_summary()
        assert summary["total_unique_crashes"] == 3
        assert summary["by_severity"]["critical"] == 2

    def test_empty_crashes(self):
        """Empty aggregator returns zero crashes."""
        agg = CrashAggregator()
        assert len(agg.get_all_crashes()) == 0
        summary = agg.get_summary()
        assert summary["total_unique_crashes"] == 0


class TestReportGenerator:
    """Test report generation."""

    def test_markdown_generation(self):
        """Markdown report file is created and parseable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            agg = CrashAggregator()
            agg.add_crash(
                {"error_type": "overflow", "stack_trace": "0x1000: func_a"},
                func_sig="test_func", apk_name="test.apk",
            )

            results = [FuzzResult(func_sig="test_func", total_runs=100, coverage_ratio=0.15)]

            config = ReportConfig(output_dir=tmpdir, format="markdown")
            gen = ReportGenerator(config)
            gen.generate(results, agg, {"apk_count": 1, "func_count": 1})

            # Check markdown file exists
            md_files = [f for f in os.listdir(tmpdir) if f.endswith(".md")]
            assert len(md_files) == 1

            # Check content
            with open(os.path.join(tmpdir, md_files[0])) as f:
                content = f.read()
            assert "MediaFuzzer" in content
            assert "overflow" in content

    def test_json_generation(self):
        """JSON report file is created and parseable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            agg = CrashAggregator()
            agg.add_crash(
                {"error_type": "uaf"},
                func_sig="test_func", apk_name="test.apk",
            )

            results = [FuzzResult(func_sig="test_func", total_runs=50)]

            config = ReportConfig(output_dir=tmpdir, format="json")
            gen = ReportGenerator(config)
            gen.generate(results, agg)

            json_files = [f for f in os.listdir(tmpdir) if f.endswith(".json")]
            assert len(json_files) == 1

            with open(os.path.join(tmpdir, json_files[0])) as f:
                data = json.load(f)
            assert data["meta"]["tool"] == "MediaFuzzer-Replica"
            assert len(data["crashes"]) == 1

    def test_empty_results_report(self):
        """Report with no crashes generates correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            agg = CrashAggregator()
            config = ReportConfig(output_dir=tmpdir)
            gen = ReportGenerator(config)
            gen.generate([], agg)

            md_files = [f for f in os.listdir(tmpdir) if f.endswith(".md")]
            assert len(md_files) == 1
