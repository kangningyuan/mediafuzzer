"""APK unpacking and SO extraction."""

import logging
import os
import shutil
import zipfile
from pathlib import Path

from config.settings import settings

logger = logging.getLogger("mediafuzzer.apk_io.extractor")


def extract_so_files(apk_path: str, output_dir: str | None = None) -> list[str]:
    """Extract native libraries (.so) from an APK file.

    APKs are ZIP files. Extracts lib/<abi>/*.so, preferring arm64-v8a.
    Creates a subdirectory named by package name.
    Returns absolute paths of extracted SO files.
    """
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    if output_dir is None:
        output_dir = settings.SO_OUTPUT_DIR

    package_name = get_apk_package_name(apk_path)
    dest_dir = os.path.join(output_dir, package_name)
    os.makedirs(dest_dir, exist_ok=True)

    preferred_abis = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
    extracted: list[str] = []
    found_abis: set[str] = set()

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            so_entries = [
                n for n in zf.namelist()
                if n.startswith("lib/") and n.endswith(".so")
            ]

            for entry in so_entries:
                # Extract ABI from path: lib/<abi>/libfoo.so
                parts = entry.split("/")
                if len(parts) != 3:
                    continue
                found_abis.add(parts[1])

            # Select best ABI
            selected_abi = None
            for abi in preferred_abis:
                if abi in found_abis:
                    selected_abi = abi
                    break
            if selected_abi is None and found_abis:
                selected_abi = sorted(found_abis)[0]

            if selected_abi is None:
                logger.info("No native libraries found in %s", apk_path)
                return extracted

            for entry in so_entries:
                parts = entry.split("/")
                if len(parts) == 3 and parts[1] == selected_abi:
                    so_name = parts[2]
                    dest_path = os.path.join(dest_dir, so_name)
                    with zf.open(entry) as src, open(dest_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(os.path.abspath(dest_path))
                    logger.debug("Extracted %s -> %s", entry, dest_path)

    except zipfile.BadZipFile:
        raise ValueError(f"Invalid APK format (not a valid ZIP): {apk_path}")

    logger.info("Extracted %d SO files from %s (ABI: %s)", len(extracted), apk_path, selected_abi)
    return extracted


def get_apk_package_name(apk_path: str) -> str:
    """Read package name from AndroidManifest.xml via androguard."""
    try:
        from androguard.core.apk import APK  # type: ignore[import-untyped]

        apk = APK(apk_path)
        name = apk.get_package()
        if name:
            return name
    except Exception as e:
        logger.warning("androguard failed to get package name from %s: %s", apk_path, e)

    # Fallback: use filename stem
    return Path(apk_path).stem


def list_apk_files(apk_dir: str | None = None) -> list[str]:
    """Recursively find .apk files in a directory."""
    target = apk_dir or settings.APK_INPUT_DIR
    if not os.path.isdir(target):
        logger.warning("APK directory does not exist: %s", target)
        return []
    return sorted(
        str(p) for p in Path(target).rglob("*.apk")
    )
