"""HTTP routes and JSON API endpoints for the webapp."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from .session_state import get_session, _DEFAULT_SID
from .pipeline_controller import PipelineController

main_bp = Blueprint("main", __name__)

_controller: PipelineController | None = None


def _get_controller() -> PipelineController:
    global _controller
    from .app import get_socketio
    if _controller is None:
        _controller = PipelineController(_DEFAULT_SID, get_socketio())
    return _controller


# --- Page Routes ---


@main_bp.route("/")
def index():
    return redirect(url_for("main.apk_page"))


@main_bp.route("/apk")
def apk_page():
    return render_template("index.html")


@main_bp.route("/filtering")
def filtering_page():
    return render_template("filtering.html")


@main_bp.route("/emulation")
def emulation_page():
    return render_template("emulation.html")


@main_bp.route("/fuzzing")
def fuzzing_page():
    return render_template("fuzzing.html")


@main_bp.route("/report")
def report_page():
    return render_template("report.html")


# --- API: APK ---


@main_bp.route("/api/apk/list")
def apk_list():
    apk_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "apk")
    os.makedirs(apk_dir, exist_ok=True)
    files = []
    for p in sorted(Path(apk_dir).rglob("*.apk")):
        stat = p.stat()
        files.append(
            {
                "name": p.name,
                "path": str(p),
                "size_mb": round(stat.st_size / (1024 * 1024), 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            }
        )
    return jsonify({"apk_dir": apk_dir, "files": files})


@main_bp.route("/api/apk/select", methods=["POST"])
def apk_select():
    data = request.get_json(silent=True) or {}
    apk_path = data.get("apk_path", "")
    if not apk_path or not os.path.isfile(apk_path):
        return jsonify({"error": "APK file not found"}), 400
    ctrl = _get_controller()
    ctrl.start_extraction(apk_path)
    return jsonify({"status": "extracting", "message": "Extraction started"})


@main_bp.route("/api/apk/status")
def apk_status():
    session = get_session(_DEFAULT_SID)
    return jsonify(
        {
            "status": session.apk_status,
            "apk_path": session.selected_apk,
            "so_files": session.extracted_sos,
            "signature_count": len(session.signatures),
        }
    )


# --- API: LLM Filtering ---


@main_bp.route("/api/filter/start", methods=["POST"])
def filter_start():
    data = request.get_json(silent=True) or {}
    skip_llm = data.get("skip_llm", False)
    concurrency = data.get("concurrency", 4)
    ctrl = _get_controller()
    ctrl.start_filtering(skip_llm=skip_llm, concurrency=concurrency)
    return jsonify({"status": "filtering", "message": "LLM filtering started"})


@main_bp.route("/api/filter/results")
def filter_results():
    session = get_session(_DEFAULT_SID)
    return jsonify(
        {
            "status": session.filter_status,
            "total": len(session.all_func_infos),
            "multimedia_count": sum(1 for f in session.all_func_infos if f.get("is_multimedia")),
            "functions": session.all_func_infos,
        }
    )


@main_bp.route("/api/filter/confirm", methods=["POST"])
def filter_confirm():
    data = request.get_json(silent=True) or {}
    selected = data.get("selected_symbols", [])
    ctrl = _get_controller()
    count = ctrl.confirm_selection(selected)
    return jsonify({"status": "confirmed", "selected_count": count})


# --- API: Emulation ---


@main_bp.route("/api/emulation/status")
def emulation_status():
    session = get_session(_DEFAULT_SID)
    return jsonify(
        {
            "status": session.emulation_status,
            "so_path": "",
            "func_symbol": session.current_func_symbol,
            "func_addr": "",
            "ready": session.emulation_ready,
            "resolved_symbols": session.resolved_symbols,
        }
    )


@main_bp.route("/api/emulation/setup", methods=["POST"])
def emulation_setup():
    data = request.get_json(silent=True) or {}
    func_symbol = data.get("func_symbol", "")
    if not func_symbol:
        return jsonify({"error": "func_symbol required"}), 400
    ctrl = _get_controller()
    ctrl.start_emulation_setup(func_symbol)
    return jsonify({"status": "setting_up", "message": "Emulation setup started"})


# --- API: Fuzzing ---


@main_bp.route("/api/fuzz/start", methods=["POST"])
def fuzz_start():
    data = request.get_json(silent=True) or {}
    max_runs = data.get("max_runs", 10000)
    timeout = data.get("timeout", 300)
    ctrl = _get_controller()
    ctrl.start_fuzzing(max_runs=max_runs, timeout=timeout)
    return jsonify({"status": "fuzzing", "message": "Fuzzing started"})


@main_bp.route("/api/fuzz/stop", methods=["POST"])
def fuzz_stop():
    ctrl = _get_controller()
    ctrl.stop_fuzzing()
    return jsonify({"status": "stopping", "message": "Stop signal sent"})


@main_bp.route("/api/fuzz/stats")
def fuzz_stats():
    session = get_session(_DEFAULT_SID)
    if not session.fuzz_worker or not session.fuzz_result:
        return jsonify(
            {
                "run_count": 0,
                "max_runs": 0,
                "coverage_ratio": 0.0,
                "covered_edges": 0,
                "crashes": 0,
                "unique_crashes": 0,
                "corpus_size": 0,
                "elapsed_seconds": 0,
                "memory_errors": 0,
                "mutations_per_sec": 0,
            }
        )
    w = session.fuzz_worker
    r = session.fuzz_result
    return jsonify(
        {
            "run_count": r.total_runs,
            "max_runs": 0,
            "coverage_ratio": w.coverage.coverage_ratio if w.coverage else 0.0,
            "covered_edges": w.coverage.covered_count if w.coverage else 0,
            "crashes": len(r.crashes),
            "unique_crashes": r.unique_crashes,
            "corpus_size": len(w._corpus) if w else 0,
            "elapsed_seconds": round(r.total_time, 1),
            "memory_errors": len(r.memory_errors),
            "mutations_per_sec": round(r.total_runs / r.total_time, 1) if r.total_time > 0 else 0,
        }
    )


# --- API: Memory ---


@main_bp.route("/api/memory/state")
def memory_state():
    session = get_session(_DEFAULT_SID)
    return jsonify(
        {
            "blocks": [],
            "violations": session.memory_violations[-20:],
            "violation_count": len(session.memory_violations),
        }
    )


# --- API: Report ---


@main_bp.route("/api/report/generate", methods=["POST"])
def report_generate():
    ctrl = _get_controller()
    ctrl.generate_report()
    return jsonify({"status": "generating", "message": "Report generation started"})


@main_bp.route("/api/report/data")
def report_data():
    session = get_session(_DEFAULT_SID)
    return jsonify(
        {
            "status": session.report_status,
            "md_path": session.report_path,
            "markdown": session.report_md,
            "json": session.report_json,
        }
    )


# --- API: Pipeline State ---


@main_bp.route("/api/pipeline/state")
def pipeline_state():
    session = get_session(_DEFAULT_SID)
    return jsonify(session.to_dict())
