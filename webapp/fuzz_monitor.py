"""Polling monitor for FuzzWorker — emits real-time stats via SocketIO."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger("mediafuzzer.webapp.monitor")

_SHARED_ROOM = "mediafuzzer"


class FuzzMonitor:
    """Polls FuzzWorker state and emits real-time stats via SocketIO."""

    def __init__(
        self,
        socketio: Any,
        sid: str,
        fuzz_worker: Any,
        interval: float = 0.5,
        max_runs: int = 0,
    ) -> None:
        self.socketio = socketio
        self.sid = sid
        self.worker = fuzz_worker
        self.interval = interval
        self._max_runs = max_runs
        self._running = False
        self._thread: threading.Thread | None = None
        self._start_time = time.monotonic()
        self._last_unique_crashes = 0
        self._last_violation_count = 0
        self._stats_history: list[dict] = []
        self._memory_emit_counter = 0

    def start(self) -> None:
        self._running = True
        self._start_time = time.monotonic()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _poll_loop(self) -> None:
        while self._running:
            try:
                stats = self._collect_stats()
                self.socketio.emit("fuzz:stats", stats, room=_SHARED_ROOM)

                if stats["unique_crashes"] > self._last_unique_crashes:
                    crashes = self.worker._result.crashes
                    if crashes:
                        latest = crashes[-1]
                        self.socketio.emit(
                            "fuzz:crash",
                            {
                                "hash": latest.get("hash", ""),
                                "error_type": latest.get("error_type", ""),
                                "input_size": latest.get("input_size", 0),
                            },
                            room=_SHARED_ROOM,
                        )
                    self._last_unique_crashes = stats["unique_crashes"]

                mem_err_count = stats["memory_errors"]
                if mem_err_count > self._last_violation_count:
                    violations = self.worker._result.memory_errors
                    if violations and len(violations) > self._last_violation_count:
                        for v in violations[self._last_violation_count :]:
                            self.socketio.emit("memory:violation", v, room=_SHARED_ROOM)
                    self._last_violation_count = mem_err_count

                self._memory_emit_counter += 1
                if self._memory_emit_counter >= 10:
                    self._memory_emit_counter = 0
                    mem_data = self._collect_memory_state()
                    self.socketio.emit("memory:state", mem_data, room=_SHARED_ROOM)

            except Exception as e:
                logger.debug("Monitor poll error: %s", e)

            time.sleep(self.interval)

    def _collect_stats(self) -> dict:
        w = self.worker
        r = w._result
        elapsed = time.monotonic() - self._start_time

        coverage_ratio = 0.0
        covered_edges = 0
        corpus_size = 0
        try:
            if w.coverage:
                coverage_ratio = w.coverage.coverage_ratio
                covered_edges = w.coverage.covered_count
        except Exception:
            pass

        try:
            corpus_size = len(w._corpus)
        except Exception:
            pass

        stats = {
            "run_count": r.total_runs,
            "max_runs": self._max_runs,
            "coverage_ratio": round(coverage_ratio, 6),
            "covered_edges": covered_edges,
            "crashes": len(r.crashes),
            "unique_crashes": r.unique_crashes,
            "corpus_size": corpus_size,
            "elapsed_seconds": round(elapsed, 1),
            "memory_errors": len(r.memory_errors),
            "mutations_per_sec": round(r.total_runs / elapsed, 1) if elapsed > 1 else 0,
        }

        self._stats_history.append(
            {
                "time": round(elapsed, 1),
                "coverage": stats["coverage_ratio"],
                "crashes": stats["unique_crashes"],
                "runs": stats["run_count"],
            }
        )

        if len(self._stats_history) > 600:
            self._stats_history = self._stats_history[-600:]

        return stats

    def _collect_memory_state(self) -> dict:
        w = self.worker
        if not w.memory_checker:
            return {"blocks": [], "violation_count": 0, "violations": []}

        try:
            state_table = w.memory_checker.state_table
            blocks = []
            items = list(state_table._blocks.items())
            for _addr, block in items[-50:]:
                blocks.append(
                    {
                        "base_addr": hex(block.base_addr),
                        "size": block.size,
                        "tag": block.tag,
                        "freed": block.freed,
                    }
                )

            violations = []
            for v in w.memory_checker.get_violations()[-20:]:
                violations.append(v if isinstance(v, dict) else str(v))

            return {
                "blocks": blocks,
                "violation_count": len(w.memory_checker.get_violations()),
                "violations": violations,
            }
        except Exception as e:
            logger.debug("Memory state collection error: %s", e)
            return {"blocks": [], "violation_count": 0, "violations": []}
