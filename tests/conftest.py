"""Shared pytest fixtures for MediaFuzzer tests."""

import os
import shutil
import tempfile

import pytest


@pytest.fixture(scope="session")
def test_output_dir():
    """Session-scoped temporary output directory."""
    d = tempfile.mkdtemp(prefix="mediafuzzer_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def temp_dir():
    """Per-test temporary directory."""
    d = tempfile.mkdtemp(prefix="mediafuzzer_unit_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def fixtures_dir():
    """Path to test fixtures directory."""
    return os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def simple_add_so(fixtures_dir):
    """Path to simple_add.so test fixture."""
    path = os.path.join(fixtures_dir, "simple_add.so")
    return path


@pytest.fixture
def jni_test_so(fixtures_dir):
    """Path to jni_test.so test fixture."""
    path = os.path.join(fixtures_dir, "jni_test.so")
    return path


@pytest.fixture
def overflow_test_so(fixtures_dir):
    """Path to overflow_test.so test fixture."""
    path = os.path.join(fixtures_dir, "overflow_test.so")
    return path


@pytest.fixture
def mock_jni_signature():
    """Create a mock JNISignature for testing."""
    from src.apk_io.static_analyzer import JNISignature, JNIParam
    return JNISignature(
        java_full_sig="com.example.MediaProcessor.decodeImage",
        native_symbol="Java_com_example_MediaProcessor_decodeImage",
        class_name="com.example.MediaProcessor",
        method_name="decodeImage",
        params=[
            JNIParam(java_type="[B", native_type="jarray", name="arg0"),
        ],
        return_type="jint",
        so_path="/tmp/test.so",
        is_dynamic=False,
    )


@pytest.fixture
def mock_multimedia_func(mock_jni_signature):
    """Create a mock MultimediaFuncInfo for testing."""
    from src.llm_interface.querier import MultimediaFuncInfo
    return MultimediaFuncInfo(
        jni_signature=mock_jni_signature,
        is_multimedia=True,
        operation_type="decoding",
        file_format="GIF",
        confidence=0.8,
    )
