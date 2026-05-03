"""Tests for config module."""

import os
import pytest

from config.settings import settings, load_settings, validate_paths
from config.file_formats import get_format, FORMAT_REGISTRY


class TestSettings:
    """Test global settings loading."""

    def test_default_values(self):
        """Default values are set without .env or env vars."""
        assert settings.COV_BITMAP_SIZE == 65536
        assert settings.MEM_SAFETY_ENABLED is True
        assert settings.MEM_TAG_BITS == 16
        assert settings.LLM_MODEL_NAME == "gpt-4o"

    def test_env_var_override(self, monkeypatch):
        """Environment variables override defaults."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-123")
        monkeypatch.setenv("COV_BITMAP_SIZE", "32768")
        load_settings()
        assert settings.LLM_API_KEY == "test-key-123"
        assert settings.COV_BITMAP_SIZE == 32768

    def test_load_settings_returns_settings(self):
        """load_settings() returns the settings object."""
        result = load_settings()
        assert result is settings


class TestFileFormats:
    """Test file format skeleton definitions."""

    def test_gif_seed_generation(self):
        """GIF seed starts with GIF89a magic."""
        gif = get_format("GIF")
        seed = gif.generate_seed()
        assert seed[:6] == b"GIF89a"

    def test_gif_header_validation(self):
        """GIF header validation works for valid and invalid data."""
        gif = get_format("GIF")
        assert gif.validate_header(b"GIF89a...") is True
        assert gif.validate_header(b"\x89PNG...") is False

    def test_jpeg_seed_generation(self):
        """JPEG seed starts with SOI marker."""
        jpeg = get_format("JPEG")
        seed = jpeg.generate_seed()
        assert seed[:2] == b"\xFF\xD8"

    def test_webp_seed_generation(self):
        """WebP seed starts with RIFF."""
        webp = get_format("WebP")
        seed = webp.generate_seed()
        assert seed[:4] == b"RIFF"

    def test_format_registry_unknown(self):
        """Requesting unknown format raises KeyError."""
        with pytest.raises(KeyError, match="UNKNOWN"):
            get_format("UNKNOWN")

    def test_format_registry_get_gif(self):
        """get_format('GIF') returns a valid skeleton."""
        gif = get_format("GIF")
        assert gif.name == "GIF"
        assert gif.magic == b"GIF89a"
