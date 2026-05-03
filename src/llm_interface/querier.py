"""LLM API calling, retry, and result parsing for multimedia function filtering."""

import hashlib
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from config.settings import settings
from src.apk_io.static_analyzer import JNISignature
from src.llm_interface.prompt_templates import (
    build_q1_prompt,
    build_q2_prompt,
    build_q3_prompt,
)

logger = logging.getLogger("mediafuzzer.llm_interface")

# Known multimedia operation types
VALID_OPERATION_TYPES = {
    "decoding", "encoding", "rendering", "clipping",
    "conversion", "mixing", "other",
}

# Known file formats
VALID_FILE_FORMATS = {
    "GIF", "JPEG", "PNG", "WebP", "MP4", "AVI", "MKV",
    "FLAC", "MP3", "AAC", "OGG", "WAV", "BMP", "TIFF", "UNKNOWN",
}


@dataclass
class MultimediaFuncInfo:
    """Result of LLM analysis for a single JNI function."""

    jni_signature: JNISignature
    is_multimedia: bool = False
    operation_type: str = ""
    file_format: str = ""
    confidence: float = 0.0
    raw_responses: list[str] = field(default_factory=list)


class LLMQuerier:
    """Handles LLM API calls with retry logic for multimedia function analysis."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        max_retries: int | None = None,
        retry_delay: float | None = None,
        temperature: float | None = None,
    ) -> None:
        self.model = model or settings.LLM_MODEL_NAME
        self._api_key = api_key or settings.LLM_API_KEY
        self._api_base = api_base or settings.LLM_API_BASE
        self.max_retries = max_retries if max_retries is not None else settings.LLM_MAX_RETRIES
        self.retry_delay = retry_delay if retry_delay is not None else settings.LLM_RETRY_DELAY
        self.temperature = temperature if temperature is not None else settings.LLM_TEMPERATURE
        self._client = None
        self._audit_path: str | None = None

    @property
    def client(self):
        """Lazy-initialize OpenAI client."""
        if self._client is None:
            from openai import OpenAI  # type: ignore[import-untyped]

            kwargs: dict = {"api_key": self._api_key}
            if self._api_base:
                kwargs["base_url"] = self._api_base
            self._client = OpenAI(**kwargs)
        return self._client

    def set_audit_path(self, path: str) -> None:
        """Set the audit log file path for LLM call recording."""
        self._audit_path = path

    def _call_with_retry(self, system: str, user: str) -> str:
        """Call LLM API with exponential backoff retry.

        Retries on RateLimitError, APITimeoutError, APIConnectionError.
        Does NOT retry on AuthenticationError, BadRequestError.
        """
        from openai import (  # type: ignore[import-untyped]
            APIConnectionError,
            APITimeoutError,
            AuthenticationError,
            BadRequestError,
            RateLimitError,
        )

        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                start = time.monotonic()
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    max_tokens=10,
                    temperature=self.temperature,
                )
                latency_ms = int((time.monotonic() - start) * 1000)
                content = response.choices[0].message.content.strip() if response.choices else ""

                self._write_audit(
                    prompt=user, response=content, latency_ms=latency_ms,
                    token_usage=getattr(response, "usage", None),
                )
                return content

            except (RateLimitError, APITimeoutError, APIConnectionError) as e:
                last_exception = e
                delay = self.retry_delay * (2 ** attempt)
                logger.warning(
                    "LLM API retryable error (attempt %d/%d): %s, retrying in %.1fs",
                    attempt + 1, self.max_retries + 1, type(e).__name__, delay,
                )
                time.sleep(delay)

            except (AuthenticationError, BadRequestError):
                raise

        raise ConnectionError(
            f"LLM API failed after {self.max_retries + 1} attempts: {last_exception}"
        )

    def _write_audit(self, prompt: str, response: str, latency_ms: int,
                     token_usage=None) -> None:
        """Write audit log entry."""
        if not self._audit_path:
            return
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "prompt_hash": hashlib.md5(prompt.encode()).hexdigest()[:8],
            "response": response,
            "model": self.model,
            "latency_ms": latency_ms,
        }
        if token_usage:
            entry["token_usage"] = {
                "prompt": getattr(token_usage, "prompt_tokens", 0),
                "completion": getattr(token_usage, "completion_tokens", 0),
            }
        try:
            with open(self._audit_path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning("Failed to write audit log: %s", e)

    def query_is_multimedia(self, sig: JNISignature) -> tuple[bool, str]:
        """Round 1: Determine if function is multimedia-related.

        Uses lenient matching — any response starting with 'yes' counts.
        """
        system, user = build_q1_prompt(sig.java_full_sig)
        response = self._call_with_retry(system, user)
        is_multi = response.lower().startswith("yes")
        return is_multi, response

    def query_operation_type(self, sig: JNISignature) -> str:
        """Round 2: Identify the multimedia operation type."""
        system, user = build_q2_prompt(sig.java_full_sig)
        response = self._call_with_retry(system, user)
        op = response.lower().strip()
        if op in VALID_OPERATION_TYPES:
            return op
        # Try to match partial
        for valid in VALID_OPERATION_TYPES:
            if valid in op:
                return valid
        return "other"

    def query_file_format(self, sig: JNISignature, operation_type: str) -> str:
        """Round 3: Identify the target file format."""
        system, user = build_q3_prompt(sig.java_full_sig, operation_type)
        response = self._call_with_retry(system, user)
        fmt = response.upper().strip()
        if fmt in VALID_FILE_FORMATS:
            return fmt
        # Try to match partial
        for valid in VALID_FILE_FORMATS:
            if valid in fmt or valid.lower() in fmt.lower():
                return valid
        return "UNKNOWN"

    def analyze_function(self, sig: JNISignature) -> MultimediaFuncInfo:
        """Full three-round Self-Heuristic Inquiry pipeline."""
        info = MultimediaFuncInfo(jni_signature=sig)

        # Round 1: Is multimedia?
        is_multi, r1 = self.query_is_multimedia(sig)
        info.raw_responses.append(r1)

        if not is_multi:
            info.is_multimedia = False
            info.confidence = 0.5
            return info

        # Round 2: Operation type
        op_type = self.query_operation_type(sig)
        info.raw_responses.append(op_type)

        # Round 3: File format
        fmt = self.query_file_format(sig, op_type)
        info.raw_responses.append(fmt)

        info.is_multimedia = True
        info.operation_type = op_type
        info.file_format = fmt
        info.confidence = 0.8

        return info


def filter_multimedia_functions(
    signatures: list[JNISignature],
    querier: LLMQuerier | None = None,
    concurrency: int = 4,
) -> list[MultimediaFuncInfo]:
    """Batch filter JNI signatures for multimedia functions using LLM.

    Uses ThreadPoolExecutor for concurrent LLM calls.
    Returns only is_multimedia=True results, sorted by confidence descending.
    """
    if querier is None:
        querier = LLMQuerier()

    results: list[MultimediaFuncInfo] = []

    def _analyze(sig: JNISignature) -> MultimediaFuncInfo:
        try:
            return querier.analyze_function(sig)
        except Exception as e:
            logger.error("LLM analysis failed for %s: %s", sig.native_symbol, e)
            return MultimediaFuncInfo(jni_signature=sig)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(_analyze, sig): sig for sig in signatures}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                sig = futures[future]
                logger.error("LLM analysis failed for %s: %s", sig.native_symbol, e)
                results.append(MultimediaFuncInfo(jni_signature=sig))

    # Filter and sort
    multimedia = [r for r in results if r.is_multimedia]
    multimedia.sort(key=lambda x: x.confidence, reverse=True)

    logger.info(
        "LLM filtering: %d/%d functions identified as multimedia",
        len(multimedia), len(signatures),
    )
    return multimedia
