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
                        self._emit(
                            "llm:progress",
                            {
                                "completed": self._llm_completed,
                                "total": self._llm_total,
                                "multimedia_count": self._llm_multimedia_count,
                            },
                        )

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
                self._emit("llm:complete", {"total": len(self.state.all_func_infos), "multimedia_count": multi_count})
                self._emit_state("filtering", "complete", f"{multi_count}/{len(self.state.all_func_infos)} multimedia")
                logger.info("LLM filtering complete: %d/%d multimedia", multi_count, len(self.state.all_func_infos))

            except Exception as e:
                logger.error("LLM filtering failed: %s", e, exc_info=True)
                self.state.filter_status = "error"
                self._emit("pipeline:error", {"message": str(e)})
                self._emit_state("filtering", "error", str(e))

        self.socketio.start_background_task(_run)

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

    def start_fuzzing(self, max_runs: int = 10000, timeout: int = 300) -> None:
        func_symbol = self.state.current_func_symbol
        if not func_symbol:
            self._emit("pipeline:error", {"message": "No function selected"})
            return

        self.state.is_fuzzing = True
        self.state.fuzz_status = "running"
        self._emit_state("fuzzing", "running", f"Fuzzing {func_symbol}")

        try:
            func_info = self._get_selected_func_info(func_symbol)
        except ValueError as e:
            self._emit("pipeline:error", {"message": str(e)})
            self.state.is_fuzzing = False
            self.state.fuzz_status = "error"
            return

        func_output_dir = os.path.join(
            self.state.output_dir,
            "fuzz_results",
            Path(func_info.jni_signature.so_path).stem,
            func_info.jni_signature.native_symbol,
        )

        def _run():
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
                    self.state.memory_violations = violations

                self.state.all_fuzz_results.append(result)

            except Exception as e:
                logger.error("Fuzzing failed: %s", e)
                self._emit("pipeline:error", {"message": str(e)})
            finally:
                self.state.is_fuzzing = False
                self.state.fuzz_status = "complete"
                if self._monitor:
                    self._monitor.stop()
                if worker:
                    try:
                        worker.teardown()
                    except Exception:
                        pass
                runs = 0
                if self.state.fuzz_result:
                    runs = self.state.fuzz_result.total_runs
                self._emit_state("fuzzing", "complete", f"Fuzzing complete: {runs} runs")

        self.socketio.start_background_task(_run)

    def stop_fuzzing(self) -> None:
        if self.state.fuzz_worker and self.state.is_fuzzing:
            self.state.fuzz_worker.stop()

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
