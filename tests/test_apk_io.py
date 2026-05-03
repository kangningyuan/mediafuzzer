"""Tests for apk_io module."""

import os
import zipfile
import pytest

from src.apk_io.so_loader import parse_elf_symbols, find_jni_symbols
from src.apk_io.extractor import extract_so_files, get_apk_package_name
from src.apk_io.static_analyzer import (
    JNISignature,
    parse_jni_bindings,
    _java_type_to_native,
    _split_method_descriptor,
    _parse_method_params,
)


class TestSoLoader:
    """Test ELF symbol parsing."""

    def test_parse_elf_symbols_nonexistent(self):
        """Parsing nonexistent file returns empty list."""
        symbols = parse_elf_symbols("/nonexistent/path.so")
        assert symbols == []

    def test_find_jni_symbols_nonexistent(self):
        """Finding JNI symbols in nonexistent file returns empty list."""
        symbols = find_jni_symbols("/nonexistent/path.so")
        assert symbols == []


class TestExtractor:
    """Test APK extraction."""

    def test_extract_nonexistent_apk(self):
        """Extracting from nonexistent APK raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            extract_so_files("/nonexistent.apk")

    def test_extract_invalid_apk(self, temp_dir):
        """Extracting from invalid APK raises ValueError."""
        bad_apk = os.path.join(temp_dir, "bad.apk")
        with open(bad_apk, "w") as f:
            f.write("not a zip file")
        with pytest.raises(ValueError, match="Invalid APK format"):
            extract_so_files(bad_apk, temp_dir)

    def test_extract_apk_no_so(self, temp_dir):
        """APK with no SO files returns empty list."""
        apk_path = os.path.join(temp_dir, "empty.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        result = extract_so_files(apk_path, temp_dir)
        assert result == []

    def test_get_package_name_fallback(self, temp_dir):
        """Package name fallback uses filename stem."""
        apk_path = os.path.join(temp_dir, "com.example.app.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("dummy.txt", "test")
        # androguard will likely fail on this non-APK, fallback to stem
        name = get_apk_package_name(apk_path)
        assert name == "com.example.app"


class TestStaticAnalyzer:
    """Test JNI signature extraction."""

    def test_java_type_to_native(self):
        """Java type to native type conversion works correctly."""
        assert _java_type_to_native("Z") == "jboolean"
        assert _java_type_to_native("I") == "jint"
        assert _java_type_to_native("J") == "jlong"
        assert _java_type_to_native("V") == "void"
        assert _java_type_to_native("Ljava/lang/String;") == "jobject"
        assert _java_type_to_native("[B") == "jarray"

    def test_split_method_descriptor(self):
        """Method descriptor splitting works correctly."""
        params, ret = _split_method_descriptor("(ILjava/lang/String;[B)V")
        assert params == "ILjava/lang/String;[B"
        assert ret == "V"

    def test_parse_method_params(self):
        """Method parameter parsing works correctly."""
        params = _parse_method_params("ILjava/lang/String;[B")
        assert params == ["I", "Ljava/lang/String;", "[B"]

    def test_parse_jni_bindings_no_symbols(self):
        """Parsing bindings from nonexistent SO returns empty list."""
        result = parse_jni_bindings("/nonexistent.so")
        assert result == []

    def test_jni_signature_heuristic(self):
        """JNI signature multimedia heuristic works."""
        sig = JNISignature(
            java_full_sig="com.example.ImageProcessor.decodeJpeg",
            native_symbol="Java_com_example_ImageProcessor_decodeJpeg",
            class_name="com.example.ImageProcessor",
            method_name="decodeJpeg",
            return_type="jint",
        )
        assert sig.is_multimedia_heuristic is True

        sig2 = JNISignature(
            java_full_sig="com.example.Utils.getString",
            native_symbol="Java_com_example_Utils_getString",
            class_name="com.example.Utils",
            method_name="getString",
            return_type="jobject",
        )
        assert sig2.is_multimedia_heuristic is False
