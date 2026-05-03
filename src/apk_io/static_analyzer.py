"""JNI function signature extraction via static analysis."""

import logging
import re
from dataclasses import dataclass, field

from src.apk_io.so_loader import find_jni_symbols, parse_elf_symbols, ELFSymbol

logger = logging.getLogger("mediafuzzer.apk_io.static_analyzer")

# Java type -> JNI native type mapping
_JAVA_TYPE_TO_NATIVE: dict[str, str] = {
    "Z": "jboolean",
    "B": "jbyte",
    "C": "jchar",
    "S": "jshort",
    "I": "jint",
    "J": "jlong",
    "F": "jfloat",
    "D": "jdouble",
    "V": "void",
}

# Heuristic keywords for multimedia pre-filtering
MULTIMEDIA_KEYWORDS: set[str] = {
    "image", "video", "audio", "media", "bitmap", "jpeg", "jpg",
    "png", "gif", "webp", "codec", "decode", "encode", "render",
    "thumbnail", "camera", "player", "recorder", "format",
    "pixel", "frame", "sample", "mp4", "mp3", "aac", "flac",
    "hevc", "h264", "h265", "avc", "opus", "vorbis",
}


@dataclass
class JNIParam:
    """A single parameter in a JNI signature."""

    java_type: str
    native_type: str
    name: str = ""

    def __post_init__(self) -> None:
        if not self.native_type:
            self.native_type = _java_type_to_native(self.java_type)
        if not self.name:
            # Will be assigned positional name later
            pass


@dataclass
class JNISignature:
    """Complete JNI function signature."""

    java_full_sig: str
    native_symbol: str
    class_name: str
    method_name: str
    params: list[JNIParam] = field(default_factory=list)
    return_type: str = ""
    so_path: str = ""
    is_dynamic: bool = False

    @property
    def is_multimedia_heuristic(self) -> bool:
        """Quick keyword-based heuristic check for multimedia relevance."""
        combined = f"{self.java_full_sig} {self.native_symbol} {self.method_name}".lower()
        return any(kw in combined for kw in MULTIMEDIA_KEYWORDS)


def _java_type_to_native(java_type: str) -> str:
    """Convert a Java type descriptor to a JNI native type."""
    if not java_type:
        return "void"
    if java_type in _JAVA_TYPE_TO_NATIVE:
        return _JAVA_TYPE_TO_NATIVE[java_type]
    if java_type.startswith("L"):
        return "jobject"
    if java_type.startswith("["):
        return "jarray"
    return "jobject"


def _parse_java_type_descriptor(desc: str, pos: int) -> tuple[str, int]:
    """Parse a single Java type descriptor starting at pos.

    Returns (type_string, next_position).
    """
    if pos >= len(desc):
        return ("", pos)

    ch = desc[pos]
    if ch in _JAVA_TYPE_TO_NATIVE:
        return (ch, pos + 1)
    if ch == "L":
        end = desc.find(";", pos)
        if end == -1:
            return (desc[pos:], len(desc))
        return (desc[pos:end + 1], end + 1)
    if ch == "[":
        inner, next_pos = _parse_java_type_descriptor(desc, pos + 1)
        return ("[" + inner, next_pos)
    return (desc[pos], pos + 1)


def _parse_method_params(params_desc: str) -> list[str]:
    """Parse parameter types from a JNI method descriptor like (ILjava/lang/String;[B)V."""
    params: list[str] = []
    pos = 0
    while pos < len(params_desc):
        typ, next_pos = _parse_java_type_descriptor(params_desc, pos)
        if typ:
            params.append(typ)
        pos = next_pos
    return params


def _decode_jni_symbol_name(symbol_name: str) -> tuple[str, str, list[str], str]:
    """Decode a Java_ prefixed JNI symbol into class, method, param types, return type.

    JNI encoding: package dots -> _, $ -> _00024, method underscores -> _1
    """
    # Strip "Java_" prefix
    encoded = symbol_name[5:] if symbol_name.startswith("Java_") else symbol_name

    # Split on _2 (which separates class from method in some conventions)
    # Standard: Java_package_Class_method
    # We need to handle _1 (literal underscore), _2 (semicolon), _3 (bracket)
    # This is complex; we do a best-effort parse

    parts = encoded.split("_")
    # Rejoin parts that were split by _1 (literal underscore in name)
    # This is a simplified decoder — full JNI name mangling is complex
    class_parts: list[str] = []
    method_parts: list[str] = []
    found_method = False

    i = 0
    current = []
    while i < len(parts):
        part = parts[i]
        if part == "1" and current:
            # Literal underscore — merge with previous
            current[-1] = current[-1] + "_"
            if i + 1 < len(parts):
                current.append(parts[i + 1])
                i += 2
                continue
        elif part == "00024" and current:
            # $ in name
            current[-1] = current[-1] + "$"
            if i + 1 < len(parts):
                current.append(parts[i + 1])
                i += 2
                continue

        current.append(part)
        i += 1

    # Heuristic: last part is method, rest is class
    if len(current) >= 2:
        method_name = current[-1]
        class_name = "/".join(current[:-1])
    elif len(current) == 1:
        method_name = current[0]
        class_name = ""
    else:
        method_name = ""
        class_name = ""

    return class_name, method_name, [], ""


def parse_jni_bindings(so_path: str, apk_path: str | None = None) -> list[JNISignature]:
    """Analyze JNI bindings in an SO file.

    1. Match Java_* prefix export symbols
    2. If apk_path provided, use androguard to parse DEX native methods
    3. Match Java native methods with SO symbols
    """
    jni_syms = find_jni_symbols(so_path)
    if not jni_syms:
        logger.warning("No JNI symbols found in %s", so_path)
        return []

    dex_native_methods: list[dict] = []
    if apk_path:
        try:
            dex_native_methods = parse_dex_native_methods(apk_path)
        except Exception as e:
            logger.warning("Failed to parse DEX from %s: %s", apk_path, e)

    signatures: list[JNISignature] = []

    # Build lookup from DEX native methods by their expected native symbol
    dex_lookup: dict[str, dict] = {}
    for dm in dex_native_methods:
        expected_sym = _java_sig_to_native_symbol(
            dm.get("class_name", ""), dm.get("method_name", ""),
        )
        dex_lookup[expected_sym] = dm

    for sym in jni_syms:
        class_name, method_name, param_types, return_type = _decode_jni_symbol_name(sym.name)

        # Try to enrich from DEX data
        dex_info = dex_lookup.get(sym.name)
        params: list[JNIParam] = []
        if dex_info:
            param_types = dex_info.get("param_types", param_types)
            return_type = dex_info.get("return_type", return_type)
            class_name = dex_info.get("class_name", class_name)
            method_name = dex_info.get("method_name", method_name)

        for idx, pt in enumerate(param_types):
            native = _java_type_to_native(pt)
            params.append(JNIParam(java_type=pt, native_type=native, name=f"arg{idx}"))

        if not return_type:
            native_ret = "void"
        else:
            native_ret = _java_type_to_native(return_type)

        java_full_sig = f"{class_name}.{method_name}" if class_name else method_name

        signatures.append(JNISignature(
            java_full_sig=java_full_sig,
            native_symbol=sym.name,
            class_name=class_name,
            method_name=method_name,
            params=params,
            return_type=native_ret,
            so_path=so_path,
            is_dynamic=False,
        ))

    logger.info(
        "Found %d JNI signatures in %s", len(signatures), so_path,
    )
    return signatures


def parse_dex_native_methods(apk_path: str) -> list[dict]:
    """Extract all native methods from DEX via androguard's DalvikVMAnalysis.

    Returns list of dicts with keys: class_name, method_name, param_types, return_type.
    """
    methods: list[dict] = []
    try:
        from androguard.core.apk import APK  # type: ignore[import-untyped]
        from androguard.core.dex import DEX  # type: ignore[import-untyped]

        apk_obj = APK(apk_path)
        for dex_bytes in apk_obj.get_all_dex():
            try:
                dex = DEX(dex_bytes)
                for cls in dex.get_classes():
                    class_name = cls.get_name()
                    if class_name:
                        class_name = class_name.strip("L").rstrip(";").replace("/", ".")
                    for method in cls.get_methods():
                        try:
                            access_flags = method.get_access_flags_string()
                            if access_flags and "native" in access_flags:
                                desc = method.get_descriptor()
                                params_str, return_str = _split_method_descriptor(desc or "")
                                param_types = _parse_method_params(params_str)
                                methods.append({
                                    "class_name": class_name,
                                    "method_name": method.get_name(),
                                    "param_types": param_types,
                                    "return_type": return_str,
                                })
                        except Exception:
                            continue
            except Exception as e:
                logger.warning("Failed to parse DEX in %s: %s", apk_path, e)
    except Exception as e:
        logger.warning("androguard failed for %s: %s", apk_path, e)
    return methods


def _split_method_descriptor(desc: str) -> tuple[str, str]:
    """Split a method descriptor like (ILjava/lang/String;)V into params and return."""
    if not desc or not desc.startswith("("):
        return ("", "")
    close = desc.find(")")
    if close == -1:
        return ("", "")
    return (desc[1:close], desc[close + 1:])


def _java_sig_to_native_symbol(class_name: str, method_name: str) -> str:
    """Convert Java class.method to expected JNI native symbol name."""
    encoded = class_name.replace(".", "_").replace("$", "_00024")
    method_encoded = method_name.replace("_", "_1")
    return f"Java_{encoded}_{method_encoded}"


def extract_all(
    apk_paths: list[str],
    output_dir: str | None = None,
) -> dict[str, list[JNISignature]]:
    """Batch process APKs: extract SOs and parse JNI signatures."""
    results: dict[str, list[JNISignature]] = {}

    for apk_path in apk_paths:
        try:
            so_paths = extract_so_files(apk_path, output_dir)
            all_sigs: list[JNISignature] = []
            for so_path in so_paths:
                sigs = parse_jni_bindings(so_path, apk_path)
                all_sigs.extend(sigs)
            results[apk_path] = all_sigs
        except (FileNotFoundError, ValueError) as e:
            logger.error("Failed to process %s: %s", apk_path, e)
            results[apk_path] = []

    total = sum(len(v) for v in results.values())
    logger.info("Batch extraction: %d APKs, %d total JNI signatures", len(apk_paths), total)
    return results


# Re-export extractor function
from src.apk_io.extractor import extract_so_files  # noqa: E402
