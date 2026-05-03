"""Base classes for file format skeleton definitions."""

import os
import struct
from dataclasses import dataclass, field


@dataclass
class FieldDef:
    """Definition of a single field in a file format skeleton."""

    name: str
    offset: int
    size: int
    fixed: bool = False
    default_value: bytes = b""
    description: str = ""

    def __post_init__(self) -> None:
        if self.default_value and len(self.default_value) != self.size:
            raise ValueError(
                f"FieldDef '{self.name}': default_value length "
                f"{len(self.default_value)} != size {self.size}"
            )


@dataclass
class FormatSkeleton:
    """Skeleton definition for a file format."""

    name: str
    magic: bytes
    fields: list[FieldDef] = field(default_factory=list)
    max_seed_size: int = 4096
    min_seed_size: int = 64

    def generate_seed(self) -> bytes:
        """Generate a valid seed file from the skeleton."""
        if not self.fields:
            return self.magic + os.urandom(max(64 - len(self.magic), 0))

        max_offset = max(f.offset + f.size for f in self.fields)
        buf = bytearray(max_offset)

        for f in self.fields:
            if f.default_value:
                buf[f.offset : f.offset + f.size] = f.default_value
            elif f.fixed:
                buf[f.offset : f.offset + f.size] = b"\x00" * f.size
            else:
                buf[f.offset : f.offset + f.size] = os.urandom(f.size)

        return bytes(buf)

    def validate_header(self, data: bytes) -> bool:
        """Check if data starts with the expected magic bytes."""
        return data[: len(self.magic)] == self.magic


# Global format registry
FORMAT_REGISTRY: dict[str, FormatSkeleton] = {}


def get_format(name: str) -> FormatSkeleton:
    """Return skeleton for a registered format, or raise KeyError."""
    if name not in FORMAT_REGISTRY:
        raise KeyError(
            f"Unknown format '{name}'. Available: {list(FORMAT_REGISTRY.keys())}"
        )
    return FORMAT_REGISTRY[name]


def register_format(name: str, skeleton: FormatSkeleton) -> None:
    """Register a new format skeleton."""
    FORMAT_REGISTRY[name] = skeleton
