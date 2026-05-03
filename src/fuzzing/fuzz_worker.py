"""Single-function fuzzing task controller."""

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from config.settings import settings
from src.llm_interface.querier import MultimediaFuncInfo
from src.fuzzing.coverage import CoverageTracker
from src.fuzzing.format_aware import FormatAwareMutator
from src.fuzzing.harness import generate_harness_source, compile_harness, HarnessBridge

logger = logging.getLogger("mediafuzzer.fuzzing.worker")


@dataclass
class FuzzResult:
    """Result of fuzzing a single function."""

    func_sig: str
    total_runs: int = 0
    total_time: float = 0.0
    crashes: list[dict] = field(default_factory=list)
    memory_errors: list[dict] = field(default_factory=list)
    coverage_ratio: float = 0.0
    unique_crashes: int = 0
    seed_corpus_dir: str = ""
    output_dir: str = ""


class FuzzWorker:
    """Controls fuzzing of a single native function.

    Uses Strategy A (pure Python-driven mutation loop) for M3-M4:
    loads seeds, iterates: select input, mutate, execute, check coverage,
    record crashes.
    """

    def __init__(self, func_info: MultimediaFuncInfo, output_dir: str) -> None:
        self.func_info = func_info
        self.output_dir = output_dir
        self.sig = func_info.jni_signature

        self.emulated_func: Any = None
        self.coverage: CoverageTracker | None = None
        self.mutator: FormatAwareMutator | None = None
        self.harness_bridge: HarnessBridge | None = None
        self.memory_checker: Any = None

        self._corpus: list[bytes] = []
        self._crash_hashes: set[str] = set()
        self._running = False
        self._result = FuzzResult(func_sig=self.sig.native_symbol)

    def setup(self) -> None:
        """Initialize emulation, coverage, mutator, harness, and seed corpus."""
        from src.emulation.qiling_env import EmulatedJNIFunc

        # Create output directories
        os.makedirs(self.output_dir, exist_ok=True)
        seeds_dir = os.path.join(self.output_dir, "seeds")
        crashes_dir = os.path.join(self.output_dir, "crashes")
        os.makedirs(seeds_dir, exist_ok=True)
        os.makedirs(crashes_dir, exist_ok=True)

        self._result.seed_corpus_dir = seeds_dir
        self._result.output_dir = self.output_dir

        # Initialize format-aware mutator
        format_name = self.func_info.file_format if self.func_info.file_format != "UNKNOWN" else None
        self.mutator = FormatAwareMutator(format_name)

        # Generate initial seed corpus
        for i in range(5):
            seed = self.mutator.generate_seed()
            seed_path = os.path.join(seeds_dir, f"seed_{i:04d}")
            with open(seed_path, "wb") as f:
                f.write(seed)
            self._corpus.append(seed)

        # Initialize emulated function
        try:
            self.emulated_func = EmulatedJNIFunc(
                so_path=self.sig.so_path,
                func_symbol=self.sig.native_symbol,
            )
            self.emulated_func.initialize()
        except Exception as e:
            logger.error("Failed to initialize emulation for %s: %s", self.sig.native_symbol, e)
            raise

        # Initialize coverage tracker
        self.coverage = CoverageTracker()
        self.coverage.register_hooks(self.emulated_func)

        # Compile and load harness
        try:
            harness_source = generate_harness_source(self.sig.native_symbol)
            harness_path = os.path.join(self.output_dir, "libharness.so")
            compile_harness(harness_source, harness_path)
            self.harness_bridge = HarnessBridge(harness_path)
        except Exception as e:
            logger.warning("Harness compilation failed (continuing without): %s", e)

        # Set up memory safety checker if enabled
        if settings.MEM_SAFETY_ENABLED:
            try:
                from src.memory_safety import TagBasedDetector, SanitizerHooks
                self.memory_checker = TagBasedDetector()
                sanitizer = SanitizerHooks(
                    self.emulated_func.ql,
                    self.memory_checker,
                    self.emulated_func.hook_manager,
                )
                sanitizer.install()
            except Exception as e:
                logger.warning("Memory safety setup failed: %s", e)

    def run(self, max_runs: int | None = None, timeout: int | None = None) -> FuzzResult:
        """Run the fuzzing loop (Strategy A: pure Python mutation).

        Args:
            max_runs: Maximum number of fuzzing iterations
            timeout: Maximum wall-clock time in seconds
        """
        max_runs = max_runs or settings.LIBFUZZER_MAX_RUNS
        timeout = timeout or settings.LIBFUZZER_TIMEOUT

        self._running = True
        start_time = time.monotonic()
        self._result.total_time = 0.0

        logger.info(
            "Starting fuzzing: %s (max_runs=%d, timeout=%ds)",
            self.sig.native_symbol, max_runs, timeout,
        )

        for run_idx in range(max_runs):
            if not self._running:
                break

            elapsed = time.monotonic() - start_time
            if elapsed >= timeout:
                logger.info("Fuzzing timeout after %ds", timeout)
                break

            # Select input from corpus
            if not self._corpus:
                self._corpus.append(self.mutator.generate_seed())

            parent = self._corpus[run_idx % len(self._corpus)]

            # Mutate
            mutated = self.mutator.mutate(parent, max_size=self.mutator.skeleton.max_seed_size if self.mutator.skeleton else 4096)

            # Save previous coverage state
            prev_bitmap = bytearray(self.coverage.bitmap) if self.coverage else bytearray()

            # Reset coverage for this run
            if self.coverage:
                self.coverage.reset()

            # Execute
            try:
                ret = self.emulated_func.call_function(bytes(mutated))

                # Check for crash (return -1 indicates error/timeout)
                if ret == -1:
                    self._record_crash(mutated, "execution_error")
                elif ret < -1:
                    self._record_crash(mutated, "crash")

            except Exception as e:
                self._record_crash(mutated, f"exception: {e}")

            # Check for new coverage
            if self.coverage:
                new_edges = self.coverage.get_new_edges(prev_bitmap)
                if new_edges:
                    # Add to corpus — this input found new paths
                    self._corpus.append(bytes(mutated))

            # Update memory errors
            if self.memory_checker:
                violations = self.memory_checker.get_violations()
                for v in violations:
                    self._result.memory_errors.append(v)

            self._result.total_runs = run_idx + 1

            # Progress logging every 1000 runs
            if (run_idx + 1) % 1000 == 0:
                logger.info(
                    "Fuzzing %s: run %d/%d, corpus=%d, crashes=%d, cov=%.2f%%",
                    self.sig.native_symbol,
                    run_idx + 1, max_runs,
                    len(self._corpus),
                    self._result.unique_crashes,
                    self.coverage.coverage_ratio * 100 if self.coverage else 0,
                )

        self._result.total_time = time.monotonic() - start_time
        self._result.coverage_ratio = self.coverage.coverage_ratio if self.coverage else 0.0

        logger.info(
            "Fuzzing complete: %s — runs=%d, time=%.1fs, crashes=%d, mem_errors=%d, cov=%.2f%%",
            self.sig.native_symbol,
            self._result.total_runs,
            self._result.total_time,
            self._result.unique_crashes,
            len(self._result.memory_errors),
            self._result.coverage_ratio * 100,
        )
        return self._result

    def _record_crash(self, input_data: bytearray, error_type: str) -> None:
        """Record a crash, deduplicating by input hash."""
        data_bytes = bytes(input_data)
        crash_hash = hashlib.md5(data_bytes).hexdigest()[:8]

        if crash_hash in self._crash_hashes:
            return  # Duplicate

        self._crash_hashes.add(crash_hash)
        self._result.unique_crashes = len(self._crash_hashes)

        # Save crash input to file
        crash_file = os.path.join(self.output_dir, "crashes", f"crash_{crash_hash}")
        with open(crash_file, "wb") as f:
            f.write(data_bytes)

        self._result.crashes.append({
            "hash": crash_hash,
            "error_type": error_type,
            "input_path": crash_file,
            "input_size": len(data_bytes),
        })

    def stop(self) -> None:
        """Signal the fuzzing loop to stop."""
        self._running = False

    def teardown(self) -> None:
        """Clean up resources."""
        if self.emulated_func:
            self.emulated_func.destroy()
        if self.harness_bridge:
            self.harness_bridge = None
