"""Per-session pipeline state management."""

from __future__ import annotations

import atexit
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("mediafuzzer.webapp.session")

_DEFAULT_SID = "default"
_sessions: dict[str, SessionState] = {}


@dataclass
class SessionState:
    """Holds all pipeline state for a single user session."""

    sid: str
    current_step: str = "apk"
    step_status: str = "idle"

    # Step 1: APK
    selected_apk: str = ""
    extracted_sos: list[str] = field(default_factory=list)
    signatures: list[dict] = field(default_factory=list)
    apk_status: str = "idle"

    # Step 2: LLM Filtering
    all_func_infos: list[dict] = field(default_factory=list)
    selected_functions: list[str] = field(default_factory=list)
    llm_skip: bool = False
    filter_status: str = "idle"
    class_coverage: dict = field(default_factory=dict)

    # Step 3: Emulation
    current_func_symbol: str = ""
    emulated_func: Any = None
    emulation_ready: bool = False
    emulation_status: str = "idle"
    resolved_symbols: list[dict] = field(default_factory=list)

    # Step 4: Fuzzing
    fuzz_worker: Any = None
    fuzz_result: Any = None
    is_fuzzing: bool = False
    fuzz_status: str = "idle"

    # Batch fuzzing
    batch_functions: list[str] = field(default_factory=list)
    batch_current_index: int = -1
    batch_total: int = 0
    batch_completed_count: int = 0
    batch_status: str = "idle"  # idle | running | complete | error | stopping

    # Step 5: Memory safety
    memory_violations: list[dict] = field(default_factory=list)
    memory_state_snapshot: dict = field(default_factory=dict)

    # Step 6: Report
    report_md: str = ""
    report_json: dict = field(default_factory=dict)
    report_path: str = ""
    report_status: str = "idle"

    output_dir: str = ""
    all_fuzz_results: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "current_step": self.current_step,
            "step_status": self.step_status,
            "selected_apk": self.selected_apk,
            "apk_status": self.apk_status,
            "signature_count": len(self.signatures),
            "so_count": len(self.extracted_sos),
            "filter_status": self.filter_status,
            "func_count": len(self.all_func_infos),
            "multimedia_count": sum(
                1 for f in self.all_func_infos if f.get("is_multimedia")
            ),
            "selected_count": len(self.selected_functions),
            "emulation_status": self.emulation_status,
            "emulation_ready": self.emulation_ready,
            "fuzz_status": self.fuzz_status,
            "is_fuzzing": self.is_fuzzing,
            "batch_status": self.batch_status,
            "batch_total": self.batch_total,
            "batch_completed_count": self.batch_completed_count,
            "batch_current_index": self.batch_current_index,
            "report_status": self.report_status,
        }


def get_session(sid: str) -> SessionState:
    if sid not in _sessions:
        _sessions[sid] = SessionState(sid=sid)
    return _sessions[sid]


def destroy_session(sid: str) -> None:
    state = _sessions.pop(sid, None)
    if not state:
        return
    if state.is_fuzzing and state.fuzz_worker:
        try:
            state.fuzz_worker.stop()
        except Exception:
            pass
    if state.emulated_func:
        try:
            state.emulated_func.destroy()
        except Exception:
            pass


def _cleanup_all() -> None:
    for sid in list(_sessions):
        destroy_session(sid)


atexit.register(_cleanup_all)
