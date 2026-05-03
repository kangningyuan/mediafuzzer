"""APK unpacking and JNI signature extraction."""

from src.apk_io.extractor import extract_so_files, get_apk_package_name
from src.apk_io.static_analyzer import parse_jni_bindings, parse_dex_native_methods
from src.apk_io.so_loader import parse_elf_symbols, find_jni_symbols, find_init_array

__all__ = [
    "extract_so_files",
    "get_apk_package_name",
    "parse_jni_bindings",
    "parse_dex_native_methods",
    "parse_elf_symbols",
    "find_jni_symbols",
    "find_init_array",
]
