"""File format registry and skeleton definitions."""

from config.file_formats.gif import GIF_SKELETON
from config.file_formats.jpeg import JPEG_SKELETON
from config.file_formats.webp import WEBP_SKELETON
from config.file_formats.base import FormatSkeleton, FieldDef, register_format, get_format, FORMAT_REGISTRY

__all__ = [
    "FormatSkeleton",
    "FieldDef",
    "FORMAT_REGISTRY",
    "get_format",
    "register_format",
    "GIF_SKELETON",
    "JPEG_SKELETON",
    "WEBP_SKELETON",
]

# Register built-in formats
register_format("GIF", GIF_SKELETON)
register_format("JPEG", JPEG_SKELETON)
register_format("WebP", WEBP_SKELETON)
