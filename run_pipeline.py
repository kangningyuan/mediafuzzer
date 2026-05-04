#!/usr/bin/env python3
"""MediaFuzzer-Replica: Main pipeline orchestration.

Orchestrates all modules from APK input to vulnerability report output.

Usage:
    python run_pipeline.py --apk-dir ./data/apks --output-dir ./output
    python run_pipeline.py --skip-llm  # Debug mode: treat all functions as multimedia
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config.settings import settings, load_settings
from src.apk_io.extractor import extract_so_files, get_apk_package_name, list_apk_files
from src.apk_io.static_analyzer import extract_all, JNISignature, JNIParam
from src.llm_interface.querier import LLMQuerier, filter_multimedia_functions, MultimediaFuncInfo
from src.fuzzing.fuzz_worker import FuzzWorker, FuzzResult
from src.reporter.crash_aggregator import CrashAggregator
from src.reporter.report_generator import ReportGenerator, ReportConfig, generate_report

logger = logging.getLogger("mediafuzzer.pipeline")


@dataclass
class PipelineConfig:
    """Configuration for the full pipeline run."""

    apk_dir: str = ""
    output_dir: str = ""
    max_workers: int = 4
    fuzz_timeout: int = 300
    fuzz_max_runs: int = 100000
    llm_concurrency: int = 4
    skip_llm: bool = False
    skip_memory_safety: bool = False


def setup_logging(output_dir: str) -> None:
    """Configure dual-output logging: console (INFO) + file (DEBUG)."""
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "pipeline.log")

    root_logger = logging.getLogger("mediafuzzer")
    root_logger.setLevel(logging.DEBUG)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root_logger.addHandler(console)

    # File handler
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
    ))
    root_logger.addHandler(file_handler)


def list_apk_files_standalone(apk_dir: str) -> list[str]:
    """Recursively find .apk files in a directory."""
    if not os.path.isdir(apk_dir):
        logger.warning("APK directory does not exist: %s", apk_dir)
        return []
    return sorted(str(p) for p in Path(apk_dir).rglob("*.apk"))


def save_signatures(signatures: dict[str, list[JNISignature]], path: str) -> None:
    """Serialize signatures to JSON."""
    data = {}
    for apk_path, sigs in signatures.items():
        data[apk_path] = [
            {
                "java_full_sig": s.java_full_sig,
                "native_symbol": s.native_symbol,
                "class_name": s.class_name,
                "method_name": s.method_name,
                "params": [
                    {"java_type": p.java_type, "native_type": p.native_type, "name": p.name}
                    for p in s.params
                ],
                "return_type": s.return_type,
                "so_path": s.so_path,
                "is_dynamic": s.is_dynamic,
            }
            for s in sigs
        ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_multimedia_funcs(funcs: list[MultimediaFuncInfo], path: str) -> None:
    """Serialize multimedia function info to JSON."""
    data = [
        {
            "native_symbol": f.jni_signature.native_symbol,
            "java_full_sig": f.jni_signature.java_full_sig,
            "so_path": f.jni_signature.so_path,
            "is_multimedia": f.is_multimedia,
            "operation_type": f.operation_type,
            "file_format": f.file_format,
            "confidence": f.confidence,
        }
        for f in funcs
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_checkpoint(output_dir: str) -> dict:
    """Load checkpoint data from a previous run."""
    checkpoint: dict = {"signatures": None, "multimedia_funcs": None, "completed_funcs": set()}

    sig_path = os.path.join(output_dir, "jni_signatures.json")
    if os.path.isfile(sig_path):
        checkpoint["signatures"] = sig_path
        logger.info("Found existing signatures: %s", sig_path)

    func_path = os.path.join(output_dir, "multimedia_functions.json")
    if os.path.isfile(func_path):
        checkpoint["multimedia_funcs"] = func_path
        logger.info("Found existing multimedia functions: %s", func_path)

    # Check for completed fuzz results
    fuzz_dir = os.path.join(output_dir, "fuzz_results")
    if os.path.isdir(fuzz_dir):
        for so_dir in os.listdir(fuzz_dir):
            so_path = os.path.join(fuzz_dir, so_dir)
            if os.path.isdir(so_path):
                for func_dir in os.listdir(so_path):
                    func_path = os.path.join(so_path, func_dir)
                    if os.path.isdir(func_path) and os.listdir(func_path):
                        checkpoint["completed_funcs"].add(f"{so_dir}/{func_dir}")

    return checkpoint


def save_checkpoint(output_dir: str, key: str, data: Any) -> None:
    """Save checkpoint data for resume support."""
    path = os.path.join(output_dir, key)
    try:
        with open(path, "w") as f:
            if isinstance(data, (dict, list)):
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                f.write(str(data))
    except Exception as e:
        logger.warning("Failed to save checkpoint %s: %s", key, e)


def fuzz_single_function(
    func_info: MultimediaFuncInfo,
    output_dir: str,
    config: PipelineConfig,
) -> FuzzResult:
    """Fuzz a single multimedia function.

    Initializes emulation, coverage, memory safety, format mutator,
    runs FuzzWorker, collects violations, and tears down.
    """
    worker = FuzzWorker(func_info, output_dir)

    try:
        worker.setup()
        result = worker.run(
            max_runs=config.fuzz_max_runs,
            timeout=config.fuzz_timeout,
        )

        # Collect memory violations
        if worker.memory_checker:
            violations = worker.memory_checker.get_violations()
            result.memory_errors.extend(violations)

        return result

    except Exception as e:
        logger.error(
            "Fuzzing failed for %s: %s", func_info.jni_signature.native_symbol, e,
        )
        return FuzzResult(
            func_sig=func_info.jni_signature.native_symbol,
            total_runs=0,
            total_time=0.0,
        )
    finally:
        worker.teardown()


def run_pipeline(config: PipelineConfig) -> str:
    """Execute the full pipeline from APK input to vulnerability report.

    Returns the output directory path.
    """
    # Step 0: Initialization
    load_settings()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_dir = config.output_dir or os.path.join(settings.OUTPUT_BASE_DIR, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    setup_logging(output_dir)
    logger.info("=== MediaFuzzer Pipeline Started ===")
    logger.info("Output directory: %s", output_dir)

    # Signal handling for graceful exit
    interrupted = [False]

    def _signal_handler(signum, frame):
        logger.info("Received SIGINT, saving checkpoint...")
        interrupted[0] = True

    signal.signal(signal.SIGINT, _signal_handler)

    # Load checkpoint
    checkpoint = load_checkpoint(output_dir)

    # Step 1: APK Preprocessing
    logger.info("Step 1: APK Preprocessing")
    apk_dir = config.apk_dir or settings.APK_INPUT_DIR
    apk_paths = list_apk_files_standalone(apk_dir)
    logger.info("Found %d APK files in %s", len(apk_paths), apk_dir)

    if not apk_paths:
        logger.warning("No APK files found, generating empty report")

    all_signatures: dict[str, list[JNISignature]] = {}
    if checkpoint["signatures"] is None:
        all_signatures = extract_all(apk_paths, os.path.join(output_dir, "so_cache"))
        save_signatures(all_signatures, os.path.join(output_dir, "jni_signatures.json"))
        save_checkpoint(output_dir, "checkpoint_signatures.json", {
            "status": "signatures_complete",
            "apk_count": len(apk_paths),
            "total_signatures": sum(len(v) for v in all_signatures.values()),
        })
    else:
        logger.info("Skipping APK preprocessing (checkpoint found)")
        # Load signatures from checkpoint file
        try:
            with open(checkpoint["signatures"]) as f:
                raw = json.load(f)
            for apk_path, sigs in raw.items():
                loaded_sigs = []
                for s in sigs:
                    # Convert params dicts to JNIParam objects if present
                    if "params" in s and isinstance(s["params"], list):
                        s["params"] = [JNIParam(**p) for p in s["params"]]
                    loaded_sigs.append(JNISignature(**s))
                all_signatures[apk_path] = loaded_sigs
        except Exception as e:
            logger.warning("Failed to load signatures from checkpoint: %s", e)

    # Flatten all signatures
    flat_signatures: list[JNISignature] = []
    for sigs in all_signatures.values():
        flat_signatures.extend(sigs)
    logger.info("Total JNI signatures: %d", len(flat_signatures))

    # Step 2: LLM Filtering
    logger.info("Step 2: LLM Multimedia Function Filtering")
    multimedia_funcs: list[MultimediaFuncInfo] = []

    if checkpoint["multimedia_funcs"] is None:
        if config.skip_llm:
            # Debug mode: treat all functions as multimedia
            for sig in flat_signatures:
                multimedia_funcs.append(MultimediaFuncInfo(
                    jni_signature=sig,
                    is_multimedia=True,
                    operation_type="other",
                    file_format="UNKNOWN",
                    confidence=0.5,
                ))
            logger.info("Skip-LLM mode: %d functions treated as multimedia", len(multimedia_funcs))
        else:
            querier = LLMQuerier()
            audit_path = os.path.join(output_dir, "llm_audit.jsonl")
            querier.set_audit_path(audit_path)
            multimedia_funcs = filter_multimedia_functions(
                flat_signatures, querier, concurrency=config.llm_concurrency,
            )

        save_multimedia_funcs(multimedia_funcs, os.path.join(output_dir, "multimedia_functions.json"))
        save_checkpoint(output_dir, "checkpoint_llm.json", {
            "status": "llm_complete",
            "multimedia_count": len(multimedia_funcs),
        })
    else:
        logger.info("Skipping LLM filtering (checkpoint found)")
        # Load multimedia functions from checkpoint file
        try:
            with open(checkpoint["multimedia_funcs"]) as f:
                raw = json.load(f)
            for item in raw:
                # Derive class_name and method_name from java_full_sig
                full_sig = item.get("java_full_sig", "")
                if "." in full_sig:
                    class_name, method_name = full_sig.rsplit(".", 1)
                else:
                    class_name, method_name = full_sig, ""
                sig = JNISignature(
                    java_full_sig=full_sig,
                    native_symbol=item.get("native_symbol", ""),
                    class_name=class_name,
                    method_name=method_name,
                    so_path=item.get("so_path", ""),
                )
                multimedia_funcs.append(MultimediaFuncInfo(
                    jni_signature=sig,
                    is_multimedia=item.get("is_multimedia", True),
                    operation_type=item.get("operation_type", "other"),
                    file_format=item.get("file_format", "UNKNOWN"),
                    confidence=item.get("confidence", 0.5),
                ))
        except Exception as e:
            logger.warning("Failed to load multimedia functions from checkpoint: %s", e)

    logger.info("Multimedia functions to fuzz: %d", len(multimedia_funcs))

    # Step 3: Fuzzing Scheduling
    logger.info("Step 3: Fuzzing Scheduling")
    fuzz_results: list[FuzzResult] = []

    for idx, func_info in enumerate(multimedia_funcs):
        if interrupted[0]:
            logger.info("Pipeline interrupted, stopping fuzzing")
            break

        func_key = f"{Path(func_info.jni_signature.so_path).stem}/{func_info.jni_signature.native_symbol}"
        if func_key in checkpoint["completed_funcs"]:
            logger.info("Skipping completed function: %s", func_key)
            continue

        logger.info(
            "Fuzzing [%d/%d]: %s",
            idx + 1, len(multimedia_funcs), func_info.jni_signature.native_symbol,
        )

        func_output_dir = os.path.join(
            output_dir, "fuzz_results",
            Path(func_info.jni_signature.so_path).stem,
            func_info.jni_signature.native_symbol,
        )

        result = fuzz_single_function(func_info, func_output_dir, config)
        fuzz_results.append(result)

    # Step 4: Report Generation
    logger.info("Step 4: Report Generation")
    aggregator = CrashAggregator()

    # Aggregate all crashes and memory errors
    for fr in fuzz_results:
        for crash in fr.crashes:
            aggregator.add_crash(crash, func_sig=fr.func_sig)
        for error in fr.memory_errors:
            aggregator.add_memory_error(error, func_sig=fr.func_sig)

    pipeline_meta = {
        "apk_count": len(apk_paths),
        "func_count": len(flat_signatures),
        "multimedia_count": len(multimedia_funcs),
        "fuzzed_count": len(fuzz_results),
        "timestamp": timestamp,
    }

    report_config = ReportConfig(output_dir=os.path.join(output_dir, "reports"))
    gen = ReportGenerator(report_config)
    gen.generate(fuzz_results, aggregator, pipeline_meta)

    logger.info("=== MediaFuzzer Pipeline Complete ===")
    logger.info("Output: %s", output_dir)
    logger.info("Unique crashes: %d", len(aggregator.get_all_crashes()))

    return output_dir


def parse_args() -> PipelineConfig:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="MediaFuzzer-Replica: LLM-guided multimedia native library fuzzer",
    )
    parser.add_argument("--apk-dir", default="", help="Directory containing APK files")
    parser.add_argument("--output-dir", default="", help="Output directory for results")
    parser.add_argument("--max-workers", type=int, default=4, help="Max parallel fuzz workers")
    parser.add_argument("--fuzz-timeout", type=int, default=300, help="Fuzzing timeout per function (seconds)")
    parser.add_argument("--fuzz-max-runs", type=int, default=100000, help="Max fuzzing iterations per function")
    parser.add_argument("--llm-concurrency", type=int, default=4, help="LLM API concurrency")
    parser.add_argument("--skip-llm", action="store_true", help="Skip LLM filtering (treat all as multimedia)")
    parser.add_argument("--skip-memory-safety", action="store_true", help="Skip memory safety detection")

    args = parser.parse_args()
    return PipelineConfig(
        apk_dir=args.apk_dir,
        output_dir=args.output_dir,
        max_workers=args.max_workers,
        fuzz_timeout=args.fuzz_timeout,
        fuzz_max_runs=args.fuzz_max_runs,
        llm_concurrency=args.llm_concurrency,
        skip_llm=args.skip_llm,
        skip_memory_safety=args.skip_memory_safety,
    )


if __name__ == "__main__":
    config = parse_args()
    run_pipeline(config)
