"""Result report generation."""

from src.reporter.crash_aggregator import CrashAggregator
from src.reporter.report_generator import ReportGenerator, generate_report

__all__ = [
    "CrashAggregator",
    "ReportGenerator",
    "generate_report",
]
