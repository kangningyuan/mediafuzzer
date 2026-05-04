"""Global configuration: paths, parameters, switches."""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("mediafuzzer.config")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class _Settings:
    """Read-only settings container. Populated by load_settings()."""

    # LLVM / LibFuzzer
    CLANG_PATH: str = "/usr/bin/clang-18"
    LIBCLANG_RT_PATH: str = "/usr/lib/llvm-18/lib/clang/18/lib/linux/"
    LIBFUZZER_TIMEOUT: int = 300
    LIBFUZZER_MAX_RUNS: int = 100000

    # Qiling emulation
    QL_ROOTFS_PATH: str = str(_PROJECT_ROOT / "rootfs" / "arm64_android")
    QL_ARCH: str = "arm64"
    QL_OS: str = "linux"
    QL_VERBOSE: int = 0
    QL_TIMEOUT: int = 500000  # microseconds (500ms per execution)

    # APK / SO paths
    APK_INPUT_DIR: str = str(_PROJECT_ROOT / "data" / "apks")
    SO_OUTPUT_DIR: str = str(_PROJECT_ROOT / "data" / "extracted_so")

    # LLM
    LLM_MODEL_NAME: str = "gpt-4o"
    LLM_API_KEY: str = ""
    LLM_API_BASE: Optional[str] = None
    LLM_MAX_RETRIES: int = 3
    LLM_RETRY_DELAY: float = 1.0
    LLM_TEMPERATURE: float = 0.0

    # Coverage
    COV_BITMAP_SIZE: int = 65536

    # Memory safety
    MEM_SAFETY_ENABLED: bool = True
    MEM_TAG_BITS: int = 16

    # Output
    OUTPUT_BASE_DIR: str = str(_PROJECT_ROOT / "output")

    def __repr__(self) -> str:
        items = {k: v for k, v in vars(type(self)).items() if k.isupper()}
        return f"<Settings {items}>"


settings = _Settings()


def load_settings(env_file: Optional[str] = None) -> _Settings:
    """Load configuration with priority: env vars > .env file > defaults.

    Converts all paths to absolute and validates key paths.
    """
    _load_dotenv(env_file)

    _apply_env_overrides()

    _resolve_paths()

    validate_paths()

    return settings


def validate_paths() -> None:
    """Check critical paths and warn (not abort) if missing."""
    critical_paths = {
        "CLANG_PATH": settings.CLANG_PATH,
        "QL_ROOTFS_PATH": settings.QL_ROOTFS_PATH,
    }
    for name, path in critical_paths.items():
        if not os.path.exists(path):
            logger.warning("Config path %s=%s does not exist", name, path)


def _load_dotenv(env_file: Optional[str] = None) -> None:
    """Load .env file if available. Silently skip if missing."""
    try:
        from dotenv import dotenv_values  # type: ignore[import-untyped]

        target = env_file or str(_PROJECT_ROOT / ".env")
        if os.path.isfile(target):
            for k, v in dotenv_values(target).items():
                if v is not None:
                    os.environ.setdefault(k, v)
    except ImportError:
        pass


def _apply_env_overrides() -> None:
    """Override settings from environment variables."""
    env_map: dict[str, tuple[type, str]] = {
        "CLANG_PATH": (str, "CLANG_PATH"),
        "LIBCLANG_RT_PATH": (str, "LIBCLANG_RT_PATH"),
        "LIBFUZZER_TIMEOUT": (int, "LIBFUZZER_TIMEOUT"),
        "LIBFUZZER_MAX_RUNS": (int, "LIBFUZZER_MAX_RUNS"),
        "QL_ROOTFS_PATH": (str, "QL_ROOTFS_PATH"),
        "QL_ARCH": (str, "QL_ARCH"),
        "QL_OS": (str, "QL_OS"),
        "QL_VERBOSE": (int, "QL_VERBOSE"),
        "QL_TIMEOUT": (int, "QL_TIMEOUT"),
        "APK_INPUT_DIR": (str, "APK_INPUT_DIR"),
        "SO_OUTPUT_DIR": (str, "SO_OUTPUT_DIR"),
        "LLM_MODEL_NAME": (str, "LLM_MODEL_NAME"),
        "LLM_API_KEY": (str, "OPENAI_API_KEY"),
        "LLM_API_BASE": (str, "LLM_API_BASE"),
        "LLM_MAX_RETRIES": (int, "LLM_MAX_RETRIES"),
        "LLM_RETRY_DELAY": (float, "LLM_RETRY_DELAY"),
        "LLM_TEMPERATURE": (float, "LLM_TEMPERATURE"),
        "COV_BITMAP_SIZE": (int, "COV_BITMAP_SIZE"),
        "MEM_SAFETY_ENABLED": (bool, "MEM_SAFETY_ENABLED"),
        "MEM_TAG_BITS": (int, "MEM_TAG_BITS"),
        "OUTPUT_BASE_DIR": (str, "OUTPUT_BASE_DIR"),
    }

    for attr, (conv, env_name) in env_map.items():
        val = os.environ.get(env_name)
        if val is not None:
            try:
                if conv is bool:
                    parsed = val.lower() in ("1", "true", "yes")
                else:
                    parsed = conv(val)
                setattr(settings, attr, parsed)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid env var %s=%s, using default", env_name, val
                )


def _resolve_paths() -> None:
    """Convert relative paths to absolute."""
    path_attrs = [
        "CLANG_PATH",
        "LIBCLANG_RT_PATH",
        "QL_ROOTFS_PATH",
        "APK_INPUT_DIR",
        "SO_OUTPUT_DIR",
        "OUTPUT_BASE_DIR",
    ]
    for attr in path_attrs:
        val = getattr(settings, attr)
        if val and not os.path.isabs(val):
            setattr(settings, attr, str(_PROJECT_ROOT / val))
