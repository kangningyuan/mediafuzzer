"""ELF symbol table parsing for SO files."""

import logging
from dataclasses import dataclass

logger = logging.getLogger("mediafuzzer.apk_io.so_loader")


@dataclass
class ELFSymbol:
    """Represents a symbol from an ELF symbol table."""

    name: str
    address: int
    size: int
    type: str


def parse_elf_symbols(so_path: str) -> list[ELFSymbol]:
    """Parse ELF .dynsym section using pyelftools.

    ARM64 SO is expected to be little-endian ELF64.
    """
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("pyelftools not installed, falling back to readelf")
        return _parse_elf_symbols_readelf(so_path)

    symbols: list[ELFSymbol] = []
    try:
        with open(so_path, "rb") as f:
            elf = ELFFile(f)
            if not elf.little_endian:
                logger.warning("SO %s is not little-endian, results may be incorrect", so_path)
            section = elf.get_section_by_name(".dynsym")
            if section is None:
                logger.warning("SO %s has no .dynsym section", so_path)
                return symbols
            for sym in section.iter_symbols():
                if sym.name and sym["st_shndx"] != "SHN_UNDEF":
                    sym_type = sym["st_info"]["type"]
                    symbols.append(ELFSymbol(
                        name=sym.name,
                        address=sym["st_value"],
                        size=sym["st_size"],
                        type=sym_type,
                    ))
    except Exception as e:
        logger.warning("Failed to parse ELF symbols from %s: %s", so_path, e)
    return symbols


def find_jni_symbols(so_path: str) -> list[ELFSymbol]:
    """Filter symbols starting with Java_ prefix."""
    all_symbols = parse_elf_symbols(so_path)
    return [s for s in all_symbols if s.name.startswith("Java_")]


def find_init_array(so_path: str) -> list[int]:
    """Parse .init_array section for dynamic registration analysis (M2+)."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    except ImportError:
        return []

    addresses: list[int] = []
    try:
        with open(so_path, "rb") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(".init_array")
            if section is None:
                return addresses
            # .init_array contains an array of function pointers (8 bytes each for ARM64)
            data = section.data()
            for i in range(0, len(data), 8):
                if i + 8 <= len(data):
                    import struct
                    addr = struct.unpack("<Q", data[i:i + 8])[0]
                    if addr != 0:
                        addresses.append(addr)
    except Exception as e:
        logger.warning("Failed to parse .init_array from %s: %s", so_path, e)
    return addresses


def _parse_elf_symbols_readelf(so_path: str) -> list[ELFSymbol]:
    """Fallback: parse ELF symbols using readelf command."""
    import subprocess
    symbols: list[ELFSymbol] = []
    try:
        result = subprocess.run(
            ["readelf", "-W", "-s", so_path],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[0] != "Symbol":
                try:
                    addr = int(parts[1], 16)
                    size = int(parts[2])
                    sym_type = parts[3]
                    name = parts[7]
                    if name and sym_type in ("FUNC", "OBJECT"):
                        symbols.append(ELFSymbol(
                            name=name, address=addr, size=size, type=sym_type,
                        ))
                except (ValueError, IndexError):
                    continue
    except Exception as e:
        logger.warning("readelf fallback failed for %s: %s", so_path, e)
    return symbols
