"""Crash deduplication and anomaly classification."""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("mediafuzzer.reporter.crash_aggregator")

# Severity ordering (higher = more severe)
_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# Error type to severity mapping
_ERROR_SEVERITY: dict[str, str] = {
    "overflow": "critical",
    "uaf": "critical",
    "double_free": "critical",
    "tag_mismatch": "high",
    "crash": "medium",
    "exception": "medium",
    "timeout": "low",
    "execution_error": "low",
}


@dataclass
class UniqueCrash:
    """A deduplicated crash record."""

    crash_hash: str
    input_data_path: str = ""
    input_data_hex: str = ""
    error_type: str = "crash"
    error_message: str = ""
    stack_trace: str = ""
    func_signature: str = ""
    apk_name: str = ""
    first_seen: str = ""
    occurrence_count: int = 1
    severity: str = "medium"

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 0)


class CrashAggregator:
    """Aggregates and deduplicates crashes and memory errors."""

    def __init__(self) -> None:
        self._crashes: dict[str, UniqueCrash] = {}  # hash -> UniqueCrash

    def add_crash(
        self,
        crash: dict,
        func_sig: str = "",
        apk_name: str = "",
    ) -> None:
        """Add a crash record with deduplication.

        Dedup strategy (priority order):
        1. Stack trace hash (SHA-256 of joined frames, first 12 hex chars)
        2. Crash address + error type
        3. Input data hash
        """
        error_type = crash.get("error_type", "crash")
        stack_trace = crash.get("stack_trace", "")
        crash_addr = crash.get("crash_addr", "")
        input_data = crash.get("input_data", b"")

        # Compute dedup hash
        if stack_trace:
            frames = stack_trace.strip().split("\n")
            dedup_hash = hashlib.sha256("".join(frames).encode()).hexdigest()[:12]
        elif crash_addr and error_type:
            dedup_hash = hashlib.md5(f"{crash_addr}:{error_type}".encode()).hexdigest()[:12]
        else:
            input_hex = input_data.hex() if isinstance(input_data, bytes) else str(input_data)
            dedup_hash = hashlib.md5(input_hex.encode()).hexdigest()[:12]

        if dedup_hash in self._crashes:
            # Duplicate — increment count
            self._crashes[dedup_hash].occurrence_count += 1
            return

        # New crash
        input_hex = ""
        if isinstance(input_data, bytes):
            input_hex = input_data[:256].hex()
        elif isinstance(input_data, str):
            input_hex = input_data[:512]

        severity = _infer_severity(error_type)

        self._crashes[dedup_hash] = UniqueCrash(
            crash_hash=dedup_hash,
            input_data_path=crash.get("input_path", ""),
            input_data_hex=input_hex,
            error_type=error_type,
            error_message=crash.get("error_message", ""),
            stack_trace=stack_trace,
            func_signature=func_sig,
            apk_name=apk_name,
            first_seen=crash.get("first_seen", ""),
            severity=severity,
        )

    def add_memory_error(
        self,
        error: dict,
        func_sig: str = "",
        apk_name: str = "",
    ) -> None:
        """Add a memory error (same flow as add_crash)."""
        self.add_crash(error, func_sig=func_sig, apk_name=apk_name)

    def get_all_crashes(self) -> list[UniqueCrash]:
        """Return all crashes sorted by severity (critical first), then by count."""
        return sorted(
            self._crashes.values(),
            key=lambda c: (-c.severity_rank, -c.occurrence_count),
        )

    def get_summary(self) -> dict:
        """Return summary statistics."""
        crashes = list(self._crashes.values())
        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_apk: dict[str, int] = {}

        for c in crashes:
            by_severity[c.severity] = by_severity.get(c.severity, 0) + 1
            by_type[c.error_type] = by_type.get(c.error_type, 0) + 1
            if c.apk_name:
                by_apk[c.apk_name] = by_apk.get(c.apk_name, 0) + 1

        return {
            "total_unique_crashes": len(crashes),
            "total_occurrences": sum(c.occurrence_count for c in crashes),
            "by_severity": by_severity,
            "by_type": by_type,
            "by_apk": by_apk,
        }


def _infer_severity(error_type: str) -> str:
    """Infer severity from error type."""
    # Check direct mapping
    if error_type in _ERROR_SEVERITY:
        return _ERROR_SEVERITY[error_type]
    # Check if error_type contains a known type
    lower = error_type.lower()
    for key, severity in _ERROR_SEVERITY.items():
        if key in lower:
            return severity
    return "medium"
