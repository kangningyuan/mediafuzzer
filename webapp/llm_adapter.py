"""LLM adapter that returns ALL functions (not just multimedia) with callbacks."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from src.apk_io.static_analyzer import JNISignature
from src.llm_interface.querier import LLMQuerier, MultimediaFuncInfo

logger = logging.getLogger("mediafuzzer.webapp.llm_adapter")


def analyze_function_with_callbacks(
    querier: LLMQuerier,
    sig: JNISignature,
    on_round_start: Callable[[int, str], None] | None = None,
) -> MultimediaFuncInfo:
    """Same 3-round logic as LLMQuerier.analyze_function but with round callbacks."""
    info = MultimediaFuncInfo(jni_signature=sig)

    # Round 1
    if on_round_start:
        on_round_start(1, sig.native_symbol)
    is_multi, r1 = querier.query_is_multimedia(sig)
    info.raw_responses.append(r1)

    if not is_multi:
        info.is_multimedia = False
        info.confidence = 0.5
        return info

    # Round 2
    if on_round_start:
        on_round_start(2, sig.native_symbol)
    op_type = querier.query_operation_type(sig)
    info.raw_responses.append(op_type)

    # Round 3
    if on_round_start:
        on_round_start(3, sig.native_symbol)
    fmt = querier.query_file_format(sig, op_type)
    info.raw_responses.append(fmt)

    info.is_multimedia = True
    info.operation_type = op_type
    info.file_format = fmt
    info.confidence = 0.8

    return info


def filter_all_functions(
    signatures: list[JNISignature],
    querier: LLMQuerier | None = None,
    concurrency: int = 4,
    on_function_done: Callable[[MultimediaFuncInfo], None] | None = None,
    on_round_start: Callable[[int, str], None] | None = None,
) -> list[MultimediaFuncInfo]:
    """Batch analyze JNI signatures — returns ALL results, not just multimedia.

    Unlike filter_multimedia_functions(), this keeps is_multimedia=False entries
    so the webapp can show the complete picture.
    """
    if querier is None:
        querier = LLMQuerier()

    results: list[MultimediaFuncInfo] = []

    def _analyze(sig: JNISignature) -> MultimediaFuncInfo:
        try:
            result = analyze_function_with_callbacks(querier, sig, on_round_start)
            if on_function_done:
                on_function_done(result)
            return result
        except Exception as e:
            logger.error("LLM analysis failed for %s: %s", sig.native_symbol, e)
            fallback = MultimediaFuncInfo(jni_signature=sig)
            if on_function_done:
                on_function_done(fallback)
            return fallback

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(_analyze, sig): sig for sig in signatures}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                sig = futures[future]
                logger.error("LLM analysis failed for %s: %s", sig.native_symbol, e)
                results.append(MultimediaFuncInfo(jni_signature=sig))

    logger.info(
        "LLM filtering: %d/%d functions identified as multimedia",
        sum(1 for r in results if r.is_multimedia),
        len(signatures),
    )
    return results
