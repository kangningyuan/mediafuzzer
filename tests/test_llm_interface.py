"""Tests for llm_interface module."""

import pytest

from src.llm_interface.prompt_templates import build_q1_prompt, build_q2_prompt, build_q3_prompt
from src.llm_interface.querier import MultimediaFuncInfo, LLMQuerier


class TestPromptTemplates:
    """Test prompt template generation."""

    def test_build_q1_prompt(self):
        """Q1 prompt includes signature and asks Yes/No."""
        system, user = build_q1_prompt("com.example.decode(Ljava/lang/String;)[B")
        assert "multimedia" in system.lower()
        assert "com.example.decode" in user
        assert "Yes" in user or "No" in user

    def test_build_q2_prompt(self):
        """Q2 prompt asks about operation type."""
        system, user = build_q2_prompt("com.example.decode")
        assert "operation" in system.lower()
        assert "com.example.decode" in user

    def test_build_q3_prompt(self):
        """Q3 prompt includes operation type and asks about format."""
        system, user = build_q3_prompt("com.example.decode", "decoding")
        assert "format" in system.lower()
        assert "decoding" in user


class TestMultimediaFuncInfo:
    """Test MultimediaFuncInfo dataclass."""

    def test_default_values(self, mock_jni_signature):
        """Default values are set correctly."""
        info = MultimediaFuncInfo(jni_signature=mock_jni_signature)
        assert info.is_multimedia is False
        assert info.confidence == 0.0
        assert info.operation_type == ""
        assert info.file_format == ""

    def test_multimedia_info_with_data(self, mock_jni_signature):
        """Multimedia info stores data correctly."""
        info = MultimediaFuncInfo(
            jni_signature=mock_jni_signature,
            is_multimedia=True,
            operation_type="decoding",
            file_format="GIF",
            confidence=0.8,
        )
        assert info.is_multimedia is True
        assert info.operation_type == "decoding"
        assert info.file_format == "GIF"
