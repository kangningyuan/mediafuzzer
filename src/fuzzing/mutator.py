"""Custom mutation strategy bridge between Python and C."""

import ctypes
import logging

from src.fuzzing.format_aware import FormatAwareMutator
from src.fuzzing.harness import CUSTOM_MUTATOR_TYPE

logger = logging.getLogger("mediafuzzer.fuzzing.mutator")


class CustomMutatorBridge:
    """Bridge Python FormatAwareMutator to C LLVMFuzzerCustomMutator via ctypes."""

    def __init__(self, format_aware: FormatAwareMutator, max_size: int = 4096) -> None:
        self.format_aware = format_aware
        self.max_size = max_size
        self._c_func: ctypes._CFuncPtr | None = None

    def _custom_mutator(self, data_ptr, size, max_size, seed) -> int:
        """ctypes callback: reads data, applies format-aware mutation, writes back."""
        try:
            # Read input data
            input_data = bytes(ctypes.string_at(data_ptr, size))

            # Apply mutation
            mutated = self.format_aware.mutate(input_data, max_size=max_size, seed=seed)

            # Write back
            write_size = min(len(mutated), max_size)
            ctypes.memmove(data_ptr, bytes(mutated[:write_size]), write_size)

            return write_size
        except Exception as e:
            logger.warning("Custom mutator error: %s", e)
            return size  # Return original size on error

    def get_c_func(self) -> ctypes._CFuncPtr:
        """Return a ctypes CFUNCTYPE wrapper for the custom mutator."""
        if self._c_func is None:
            self._c_func = CUSTOM_MUTATOR_TYPE(self._custom_mutator)
        return self._c_func
