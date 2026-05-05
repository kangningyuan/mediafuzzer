"""Per-session pipeline orchestration — bridges web layer to existing pipeline code."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from config.settings import load_settings, settings
from src.apk_io.extractor import extract_so_files, get_apk_package_name
from src.apk_io.static_analyzer import JNISignature, JNIParam, extract_all
from src.llm_interface.querier import LLMQuerier, MultimediaFuncInfo
from src.fuzzing.fuzz_worker import FuzzWorker, FuzzResult
from src.reporter.crash_aggregator import CrashAggregator
from src.reporter.report_generator import ReportGenerator, ReportConfig

from .session_state import get_session, SessionState, _DEFAULT_SID
from .llm_adapter import filter_all_functions
from .fuzz_monitor import FuzzMonitor

logger = logging.getLogger("mediafuzzer.webapp.controller")

_SHARED_ROOM = "mediafuzzer"


def _serialize_signature(sig: JNISignature) -> dict:
    return {
        "java_full_sig": sig.java_full_sig,
        "native_symbol": sig.native_symbol,
        "class_name": sig.class_name,
        "method_name": sig.method_name,
        "params": [
            {"java_type": p.java_type, "native_type": p.native_type, "name": p.name}
            for p in sig.params
        ],
        "return_type": sig.return_type,
        "so_path": sig.so_path,
        "is_dynamic": sig.is_dynamic,
    }


def _serialize_func_info(info: MultimediaFuncInfo) -> dict:
    return {
        "native_symbol": info.jni_signature.native_symbol,
        "java_full_sig": info.jni_signature.java_full_sig,
        "so_path": info.jni_signature.so_path,
        "class_name": info.jni_signature.class_name,
        "method_name": info.jni_signature.method_name,
        "is_multimedia": info.is_multimedia,
        "operation_type": info.operation_type,
        "file_format": info.file_format,
        "confidence": info.confidence,
    }


def _deserialize_signature(data: dict) -> JNISignature:
    params = []
    for p in data.get("params", []):
        params.append(JNIParam(**p))
    return JNISignature(
        java_full_sig=data["java_full_sig"],
        native_symbol=data["native_symbol"],
        class_name=data.get("class_name", ""),
        method_name=data.get("method_name", ""),
        params=params,
        return_type=data.get("return_type", ""),
        so_path=data.get("so_path", ""),
        is_dynamic=data.get("is_dynamic", False),
    )


class PipelineController:
    """Orchestrates pipeline steps for a single user session."""

    def __init__(self, sid: str, socketio: Any) -> None:
        self.sid = sid
        self.socketio = socketio
        self.state = get_session(_DEFAULT_SID)
        self._llm_completed = 0
        self._llm_total = 0
        self._llm_multimedia_count = 0
        self._monitor: FuzzMonitor | None = None
        self._flat_signatures: list[JNISignature] = []

    def _emit(self, event: str, data: dict) -> None:
        self.socketio.emit(event, data, room=_SHARED_ROOM)

    def _emit_state(self, step: str, status: str, message: str = "") -> None:
        self._emit("pipeline:state", {"step": step, "status": status, "message": message})
        self.state.current_step = step
        self.state.step_status = status

    # --- Step 1: APK Extraction ---

    def start_extraction(self, apk_path: str) -> None:
        self.state.selected_apk = apk_path
        self.state.apk_status = "extracting"
        self._emit_state("apk", "running", f"Extracting {os.path.basename(apk_path)}")

        def _run():
            try:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                output_dir = os.path.join(settings.OUTPUT_BASE_DIR, f"webapp_{timestamp}")
                os.makedirs(output_dir, exist_ok=True)
                self.state.output_dir = output_dir
                logger.info("APK extraction started: %s", apk_path)

                so_cache = os.path.join(output_dir, "so_cache")
                self._emit("apk:extracting", {"apk_path": apk_path, "progress": "Extracting SO files..."})

                so_files = extract_so_files(apk_path, so_cache)
                self.state.extracted_sos = so_files
                logger.info("Extracted %d SO files", len(so_files))

                self._emit("apk:extracting", {"apk_path": apk_path, "progress": "Parsing JNI signatures..."})

                all_sigs = extract_all([apk_path], so_cache)
                flat: list[JNISignature] = []
                for sigs in all_sigs.values():
                    flat.extend(sigs)
                self._flat_signatures = flat
                self.state.signatures = [_serialize_signature(s) for s in flat]
                logger.info("Found %d JNI signatures", len(flat))

                sig_path = os.path.join(output_dir, "jni_signatures.json")
                with open(sig_path, "w") as f:
                    json.dump(self.state.signatures, f, indent=2, ensure_ascii=False)

                self.state.apk_status = "complete"
                self._emit(
                    "apk:extracted",
                    {
                        "apk_path": apk_path,
                        "signature_count": len(flat),
                        "so_files": so_files,
                    },
                )
                self._emit_state("apk", "complete", f"Extracted {len(flat)} JNI signatures")
                logger.info("APK extraction complete: %d signatures", len(flat))

            except Exception as e:
                logger.error("APK extraction failed: %s", e, exc_info=True)
                self.state.apk_status = "error"
                self._emit("pipeline:error", {"message": str(e)})
                self._emit_state("apk", "error", str(e))

        self.socketio.start_background_task(_run)

    # --- Step 2: LLM Filtering ---

    def start_filtering(self, skip_llm: bool = False, concurrency: int = 4) -> None:
        self.state.llm_skip = skip_llm
        self.state.filter_status = "running"
        self._llm_completed = 0
        self._llm_total = len(self._flat_signatures)
        self._llm_multimedia_count = 0

        if not self._flat_signatures and self.state.signatures:
            self._flat_signatures = [_deserialize_signature(s) for s in self.state.signatures]
            self._llm_total = len(self._flat_signatures)

        self._emit_state("filtering", "running", "Starting LLM filtering...")

        def _run():
            try:
                if skip_llm:
                    logger.info("Skip-LLM mode: treating all %d functions as multimedia", self._llm_total)
                    all_infos: list[MultimediaFuncInfo] = []
                    for sig in self._flat_signatures:
                        info = MultimediaFuncInfo(
                            jni_signature=sig,
                            is_multimedia=True,
                            operation_type="other",
                            file_format="UNKNOWN",
                            confidence=0.5,
                        )
                        all_infos.append(info)
                    self.state.all_func_infos = [_serialize_func_info(i) for i in all_infos]
                else:
                    logger.info("LLM filtering started: %d functions, concurrency=%d", self._llm_total, concurrency)
                    querier = LLMQuerier()
                    audit_path = os.path.join(self.state.output_dir, "llm_audit.jsonl")
                    querier.set_audit_path(audit_path)

                    def _on_round_start(round_num: int, symbol: str) -> None:
                        logger.debug("LLM round %d for %s", round_num, symbol)
                        self._emit("llm:round_start", {"round": round_num, "signature": symbol})

                    def _on_function_done(info: MultimediaFuncInfo) -> None:
                        self._llm_completed += 1
                        if info.is_multimedia:
                            self._llm_multimedia_count += 1
                        # Append to session state in real-time so poll API can serve them
                        self.state.all_func_infos.append(_serialize_func_info(info))
                        label = "multimedia" if info.is_multimedia else "non-media"
                        logger.info(
                            "[%d/%d] %s -> %s (%s, %s, conf=%.1f)",
                            self._llm_completed, self._llm_total,
                            info.jni_signature.native_symbol, label,
                            info.operation_type or "-", info.file_format or "-",
                            info.confidence,
                        )
                        self._emit("llm:function_done", _serialize_func_info(info))
                        progress_data = {
                            "completed": self._llm_completed,
                            "total": self._llm_total,
                            "multimedia_count": self._llm_multimedia_count,
                        }
                        # Include class coverage every 10 functions or near end
                        if self._llm_completed % 10 == 0 or self._llm_completed == self._llm_total:
                            coverage = self._compute_class_coverage()
                            progress_data["class_coverage"] = coverage
                        self._emit("llm:progress", progress_data)

                    all_infos = filter_all_functions(
                        self._flat_signatures,
                        querier,
                        concurrency=concurrency,
                        on_function_done=_on_function_done,
                        on_round_start=_on_round_start,
                    )
                    # all_func_infos already populated incrementally in _on_function_done

                func_path = os.path.join(self.state.output_dir, "multimedia_functions.json")
                with open(func_path, "w") as f:
                    json.dump(self.state.all_func_infos, f, indent=2, ensure_ascii=False)

                self.state.filter_status = "complete"
                multi_count = sum(1 for f in self.state.all_func_infos if f.get("is_multimedia"))
                coverage = self._compute_class_coverage()
                self.state.class_coverage = coverage
                self._emit("llm:complete", {
                    "total": len(self.state.all_func_infos),
                    "multimedia_count": multi_count,
                    "class_coverage": coverage,
                })
                self._emit_state("filtering", "complete",
                    f"{multi_count}/{len(self.state.all_func_infos)} multimedia, "
                    f"class coverage {coverage['coverage_ratio']:.1%}")
                logger.info(
                    "LLM filtering complete: %d/%d multimedia, class coverage %.1f%% (%d tagged classes)",
                    multi_count, len(self.state.all_func_infos),
                    coverage["coverage_ratio"] * 100, coverage["tagged_class_count"],
                )

            except Exception as e:
                logger.error("LLM filtering failed: %s", e, exc_info=True)
                self.state.filter_status = "error"
                self._emit("pipeline:error", {"message": str(e)})
                self._emit_state("filtering", "error", str(e))

        self.socketio.start_background_task(_run)

    def _compute_class_coverage(self) -> dict:
        """Compute same-class multimedia coverage.

        A class is "multimedia-tagged" if LLM marks at least one function in it
        as multimedia. The denominator is ALL functions belonging to those tagged
        classes, not just the ones LLM identified. This measures how thoroughly
        LLM covers the multimedia-related classes.
        """
        func_infos = self.state.all_func_infos
        if not func_infos:
            return {"llm_multimedia": 0, "same_class_total": 0, "coverage_ratio": 0.0,
                    "tagged_classes": [], "tagged_class_count": 0}

        # Find classes with at least one LLM-identified multimedia function
        multimedia_classes: set[str] = set()
        for f in func_infos:
            if f.get("is_multimedia") and f.get("class_name"):
                multimedia_classes.add(f["class_name"])

        # Count all functions in those tagged classes
        same_class_total = 0
        llm_multimedia = 0
        for f in func_infos:
            if f.get("class_name") in multimedia_classes:
                same_class_total += 1
            if f.get("is_multimedia"):
                llm_multimedia += 1

        coverage_ratio = llm_multimedia / same_class_total if same_class_total > 0 else 0.0

        return {
            "llm_multimedia": llm_multimedia,
            "same_class_total": same_class_total,
            "coverage_ratio": round(coverage_ratio, 4),
            "tagged_classes": sorted(multimedia_classes),
            "tagged_class_count": len(multimedia_classes),
        }

    def confirm_selection(self, selected_symbols: list[str]) -> int:
        self.state.selected_functions = selected_symbols
        return len(selected_symbols)

    # --- Step 3: Emulation Setup ---

    def start_emulation_setup(self, func_symbol: str) -> None:
        self.state.current_func_symbol = func_symbol
        self.state.emulation_status = "setting_up"
        self.state.emulation_ready = False
        self._emit_state("emulation", "running", f"Setting up emulation for {func_symbol}")

        func_dict = None
        for f in self.state.all_func_infos:
            if f["native_symbol"] == func_symbol:
                func_dict = f
                break

        if not func_dict:
            for s in self.state.signatures:
                if s["native_symbol"] == func_symbol:
                    func_dict = {
                        "native_symbol": s["native_symbol"],
                        "so_path": s["so_path"],
                        "java_full_sig": s["java_full_sig"],
                        "class_name": s.get("class_name", ""),
                        "method_name": s.get("method_name", ""),
                        "is_multimedia": True,
                        "operation_type": "other",
                        "file_format": "UNKNOWN",
                        "confidence": 0.5,
                    }
                    break

        if not func_dict:
            self._emit("pipeline:error", {"message": f"Function {func_symbol} not found"})
            self.state.emulation_status = "error"
            return

        def _run():
            try:
                from src.emulation.qiling_env import EmulatedJNIFunc
                from src.apk_io.so_loader import find_jni_symbols

                so_path = func_dict["so_path"]
                self._emit("emulation:setup", {"so_path": so_path, "func_symbol": func_symbol})

                if self.state.emulated_func:
                    try:
                        self.state.emulated_func.destroy()
                    except Exception:
                        pass

                emu = EmulatedJNIFunc(so_path=so_path, func_symbol=func_symbol)
                emu.initialize()

                self.state.emulated_func = emu
                self.state.emulation_ready = True

                symbols = []
                try:
                    for sym in find_jni_symbols(so_path):
                        symbols.append({"name": sym.name, "address": hex(sym.address), "size": sym.size})
                except Exception:
                    pass
                self.state.resolved_symbols = symbols

                func_addr = ""
                if hasattr(emu, "_func_addr") and emu._func_addr:
                    func_addr = hex(emu._func_addr)

                self.state.emulation_status = "ready"
                self._emit(
                    "emulation:ready",
                    {"so_path": so_path, "func_symbol": func_symbol, "func_addr": func_addr},
                )
                self._emit("emulation:symbols", {"symbols": symbols})
                self._emit_state("emulation", "complete", f"Emulation ready: {func_symbol}")

            except Exception as e:
                logger.error("Emulation setup failed: %s", e)
                self.state.emulation_status = "error"
                self.state.emulation_ready = False
                self._emit("pipeline:error", {"message": str(e)})
                self._emit_state("emulation", "error", str(e))

        self.socketio.start_background_task(_run)

    # --- Step 4: Fuzzing ---

    def _get_selected_func_info(self, func_symbol: str) -> MultimediaFuncInfo:
        sig_data = None
        func_data = None

        for f in self.state.all_func_infos:
            if f["native_symbol"] == func_symbol:
                func_data = f
                break

        for s in self.state.signatures:
            if s["native_symbol"] == func_symbol:
                sig_data = s
                break

        if not sig_data:
            raise ValueError(f"Signature not found for {func_symbol}")

        sig = _deserialize_signature(sig_data)

        return MultimediaFuncInfo(
            jni_signature=sig,
            is_multimedia=func_data.get("is_multimedia", True) if func_data else True,
            operation_type=func_data.get("operation_type", "other") if func_data else "other",
            file_format=func_data.get("file_format", "UNKNOWN") if func_data else "UNKNOWN",
            confidence=func_data.get("confidence", 0.5) if func_data else 0.5,
        )

    def _fuzz_single_function(
        self, func_symbol: str, max_runs: int, timeout: int
    ) -> FuzzResult | None:
        """Fuzz a single function. Manages FuzzWorker lifecycle + FuzzMonitor.

        Returns the FuzzResult, or None on error.
        """
        try:
            func_info = self._get_selected_func_info(func_symbol)
        except ValueError as e:
            logger.error("Cannot fuzz %s: %s", func_symbol, e)
            return None

        func_output_dir = os.path.join(
            self.state.output_dir,
            "fuzz_results",
            Path(func_info.jni_signature.so_path).stem,
            func_info.jni_signature.native_symbol,
        )

        worker = None
        try:
            worker = FuzzWorker(func_info, func_output_dir)
            worker.setup()
            self.state.fuzz_worker = worker

            monitor = FuzzMonitor(
                self.socketio, self.sid, worker, interval=0.5, max_runs=max_runs
            )
            monitor.start()
            self._monitor = monitor

            result = worker.run(max_runs=max_runs, timeout=timeout)
            self.state.fuzz_result = result

            if worker.memory_checker:
                violations = worker.memory_checker.get_violations()
                result.memory_errors.extend(violations)
                self.state.memory_violations.extend(violations)

            self.state.all_fuzz_results.append(result)
            return result

        except Exception as e:
            logger.error("Fuzzing %s failed: %s", func_symbol, e)
            self._emit("pipeline:error", {"message": f"Fuzzing {func_symbol} failed: {e}"})
            return None
        finally:
            self.state.fuzz_worker = None
            if self._monitor:
                self._monitor.stop()
                self._monitor = None
            if worker:
                try:
                    worker.teardown()
                except Exception:
                    pass

    def start_fuzzing(self, max_runs: int = 10000, timeout: int = 300) -> None:
        """Fuzz a single function (backward-compatible entry point)."""
        func_symbol = self.state.current_func_symbol
        if not func_symbol:
            self._emit("pipeline:error", {"message": "No function selected"})
            return

        self.state.is_fuzzing = True
        self.state.fuzz_status = "running"
        self._emit_state("fuzzing", "running", f"Fuzzing {func_symbol}")

        def _run():
            result = self._fuzz_single_function(func_symbol, max_runs, timeout)
            self.state.is_fuzzing = False
            self.state.fuzz_status = "complete"
            runs = result.total_runs if result else 0
            self._emit_state("fuzzing", "complete", f"Fuzzing complete: {runs} runs")

        self.socketio.start_background_task(_run)

    def start_batch_fuzzing(
        self, func_symbols: list[str], max_runs: int = 10000, timeout: int = 300
    ) -> None:
        """Fuzz multiple functions sequentially."""
        # Filter out already-completed functions (resume support)
        completed_syms = set()
        for r in self.state.all_fuzz_results:
            if isinstance(r, FuzzResult):
                completed_syms.add(r.func_sig)

        remaining = [s for s in func_symbols if s not in completed_syms]

        if not remaining:
            logger.info("All %d functions already completed", len(func_symbols))
            self.state.batch_status = "complete"
            self.state.batch_total = len(func_symbols)
            self.state.batch_completed_count = len(func_symbols)
            self.state.batch_current_index = -1
            self._emit("batch:complete", {
                "total": len(func_symbols),
                "total_crashes": 0,
                "total_unique_crashes": 0,
                "total_runs": 0,
                "elapsed": 0,
                "skipped": len(func_symbols),
            })
            return

        self.state.batch_functions = remaining
        self.state.batch_total = len(remaining)
        self.state.batch_completed_count = len(func_symbols) - len(remaining)
        self.state.batch_current_index = -1
        self.state.batch_status = "running"
        self.state.is_fuzzing = True
        self.state.fuzz_status = "running"

        # Track how many were already done before this batch started
        already_done = len(func_symbols) - len(remaining)
        batch_start = time.monotonic()

        self._emit_state("fuzzing", "running", f"Batch fuzzing: {len(remaining)} functions")

        def _run():
            total_crashes = 0
            total_unique_crashes = 0
            total_runs = 0

            for idx, func_symbol in enumerate(remaining):
                # Check if batch was stopped
                if self.state.batch_status == "stopping":
                    logger.info("Batch fuzzing stopped by user at %d/%d", idx, len(remaining))
                    break

                self.state.batch_current_index = idx
                self.state.current_func_symbol = func_symbol

                so_path = ""
                for f in self.state.all_func_infos:
                    if f["native_symbol"] == func_symbol:
                        so_path = f.get("so_path", "")
                        break

                self._emit("batch:func_start", {
                    "index": already_done + idx,
                    "total": len(func_symbols),
                    "symbol": func_symbol,
                    "so_path": so_path,
                })
                logger.info(
                    "Batch [%d/%d] Fuzzing: %s",
                    already_done + idx + 1, len(func_symbols), func_symbol,
                )

                result = self._fuzz_single_function(func_symbol, max_runs, timeout)

                if result:
                    total_crashes += len(result.crashes)
                    total_unique_crashes += result.unique_crashes
                    total_runs += result.total_runs

                self.state.batch_completed_count += 1

                self._emit("batch:func_complete", {
                    "index": already_done + idx,
                    "total": len(func_symbols),
                    "symbol": func_symbol,
                    "runs": result.total_runs if result else 0,
                    "crashes": len(result.crashes) if result else 0,
                    "unique_crashes": result.unique_crashes if result else 0,
                    "coverage_ratio": result.coverage_ratio if result else 0.0,
                    "elapsed": round(result.total_time, 1) if result else 0,
                    "memory_errors": len(result.memory_errors) if result else 0,
                    "status": "complete" if result else "error",
                })
                self._emit("batch:progress", {
                    "completed": self.state.batch_completed_count,
                    "total": len(func_symbols),
                    "total_crashes": total_crashes,
                    "total_unique_crashes": total_unique_crashes,
                    "total_runs": total_runs,
                })

            # Batch done
            was_stopping = self.state.batch_status == "stopping"
            self.state.batch_status = "complete"
            self.state.batch_current_index = -1
            self.state.is_fuzzing = False
            self.state.fuzz_status = "complete"

            elapsed = round(time.monotonic() - batch_start, 1)
            self._emit("batch:complete", {
                "total": len(func_symbols),
                "total_crashes": total_crashes,
                "total_unique_crashes": total_unique_crashes,
                "total_runs": total_runs,
                "elapsed": elapsed,
                "stopped_early": was_stopping,
            })
            self._emit_state(
                "fuzzing", "complete",
                f"Batch complete: {self.state.batch_completed_count}/{len(func_symbols)} functions, "
                f"{total_unique_crashes} unique crashes",
            )
            logger.info(
                "Batch fuzzing complete: %d/%d functions, %d unique crashes, %.1fs",
                self.state.batch_completed_count, len(func_symbols),
                total_unique_crashes, elapsed,
            )

        self.socketio.start_background_task(_run)

    def stop_fuzzing(self) -> None:
        if self.state.fuzz_worker and self.state.is_fuzzing:
            self.state.fuzz_worker.stop()
        if self.state.batch_status == "running":
            self.state.batch_status = "stopping"

    # --- Step 6: Report ---

    def generate_report(self) -> None:
        self.state.report_status = "generating"
        self._emit_state("report", "running", "Generating report...")

        try:
            aggregator = CrashAggregator()
            results = self.state.all_fuzz_results
            if not results and self.state.fuzz_result:
                results = [self.state.fuzz_result]

            for fr in results:
                if not isinstance(fr, FuzzResult):
                    continue
                for crash in fr.crashes:
                    aggregator.add_crash(crash, func_sig=fr.func_sig)
                for error in fr.memory_errors:
                    aggregator.add_memory_error(error, func_sig=fr.func_sig)

            pipeline_meta = {
                "apk_count": 1 if self.state.selected_apk else 0,
                "func_count": len(self.state.signatures),
                "multimedia_count": sum(
                    1 for f in self.state.all_func_infos if f.get("is_multimedia")
                ),
                "fuzzed_count": len(results),
            }

            report_config = ReportConfig(output_dir=os.path.join(self.state.output_dir, "reports"))
            gen = ReportGenerator(report_config)
            gen.generate(results, aggregator, pipeline_meta)

            report_dir = os.path.join(self.state.output_dir, "reports")
            md_files = sorted(Path(report_dir).glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
            json_files = sorted(Path(report_dir).glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

            self.state.report_path = str(md_files[0]) if md_files else ""
            if md_files:
                with open(md_files[0]) as f:
                    self.state.report_md = f.read()
            if json_files:
                with open(json_files[0]) as f:
                    self.state.report_json = json.load(f)

            self.state.report_status = "ready"
            self._emit("report:ready", {
                "md_path": str(md_files[0]) if md_files else "",
                "json_path": str(json_files[0]) if json_files else "",
                "summary": aggregator.get_summary(),
            })
            self._emit_state("report", "complete", "Report generated")

        except Exception as e:
            logger.error("Report generation failed: %s", e)
            self.state.report_status = "error"
            self._emit("pipeline:error", {"message": str(e)})
            self._emit_state("report", "error", str(e))
