"""Tests for pipeline module."""

import os
import tempfile

import pytest

from src.fuzzing.fuzz_worker import FuzzResult


class TestPipelineConfig:
    """Test pipeline configuration."""

    def test_default_config(self):
        """Default config values are set."""
        from run_pipeline import PipelineConfig
        config = PipelineConfig()
        assert config.max_workers == 4
        assert config.fuzz_timeout == 300
        assert config.skip_llm is False

    def test_skip_llm_config(self):
        """Skip-LLM flag works."""
        from run_pipeline import PipelineConfig
        config = PipelineConfig(skip_llm=True)
        assert config.skip_llm is True


class TestPipelineHelpers:
    """Test pipeline helper functions."""

    def test_list_apk_files_empty_dir(self, temp_dir):
        """Empty directory returns no APK files."""
        from run_pipeline import list_apk_files_standalone
        result = list_apk_files_standalone(temp_dir)
        assert result == []

    def test_list_apk_files_nonexistent(self):
        """Nonexistent directory returns empty list."""
        from run_pipeline import list_apk_files_standalone
        result = list_apk_files_standalone("/nonexistent/path")
        assert result == []

    def test_save_and_load_signatures(self, temp_dir):
        """Signatures can be saved to JSON."""
        from run_pipeline import save_signatures
        from src.apk_io.static_analyzer import JNISignature

        sigs = {
            "test.apk": [
                JNISignature(
                    java_full_sig="com.test.method",
                    native_symbol="Java_com_test_method",
                    class_name="com.test",
                    method_name="method",
                    return_type="jint",
                )
            ]
        }
        path = os.path.join(temp_dir, "signatures.json")
        save_signatures(sigs, path)
        assert os.path.isfile(path)

        import json
        with open(path) as f:
            data = json.load(f)
        assert "test.apk" in data
