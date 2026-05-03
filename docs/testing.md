# 测试策略与用例开发文档

## 1. 概述

本文档定义 MediaFuzzer-Replica 项目的测试策略、测试用例和测试基础设施。测试按模块和里程碑组织，覆盖单元测试、集成测试和端到端测试。

## 2. 测试文件结构

```
tests/
├── test_apk_io.py           # APK I/O 模块测试
├── test_llm_interface.py    # LLM 接口模块测试
├── test_emulation.py        # 模拟执行模块测试
├── test_fuzzing.py          # 模糊测试模块测试
├── test_memory_safety.py    # 内存安全检测测试
├── test_config.py           # 配置模块测试
├── test_reporter.py         # 报告模块测试
├── test_pipeline.py         # 端到端流水线测试
├── conftest.py              # pytest 共享 fixture
└── fixtures/                # 测试固件
    ├── minimal_apk/         # 极简测试 APK 源码
    │   ├── app/
    │   │   └── src/main/java/com/test/
    │   │       └── NativeLib.java
    │   ├── jni/
    │   │   ├── CMakeLists.txt
    │   │   └── native_lib.c
    │   └── build.sh
    ├── simple_add.so         # 极简 SO（int add(int, int)）
    ├── jni_test.so           # 含 JNI 调用的 SO
    ├── overflow_test.so      # 含 CWE-122 漏洞的 SO
    ├── uaf_test.so           # 含 CWE-416 漏洞的 SO
    └── double_free_test.so   # 含 CWE-415 漏洞的 SO
```

## 3. 测试框架配置

### 3.1 pytest 配置

在 `pyproject.toml` 或 `pytest.ini` 中：

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    unit: 单元测试
    integration: 集成测试
    e2e: 端到端测试
    slow: 慢速测试
    requires_llm: 需要 LLM API
    requires_qiling: 需要 Qiling rootfs
    requires_clang: 需要 Clang 编译器
```

### 3.2 conftest.py

```python
# tests/conftest.py

import pytest
import os
import tempfile
import shutil

@pytest.fixture(scope="session")
def test_output_dir():
    """创建临时输出目录，会话结束后清理"""
    d = tempfile.mkdtemp(prefix="mediafuzzer_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)

@pytest.fixture
def temp_dir():
    """每个测试独立的临时目录"""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)

@pytest.fixture(scope="session")
def fixtures_dir():
    """测试固件目录"""
    return os.path.join(os.path.dirname(__file__), "fixtures")

@pytest.fixture(scope="session")
def simple_add_so(fixtures_dir):
    """极简 add SO 路径"""
    path = os.path.join(fixtures_dir, "simple_add.so")
    if not os.path.exists(path):
        pytest.skip("simple_add.so not built")
    return path

@pytest.fixture(scope="session")
def jni_test_so(fixtures_dir):
    """JNI 测试 SO 路径"""
    path = os.path.join(fixtures_dir, "jni_test.so")
    if not os.path.exists(path):
        pytest.skip("jni_test.so not built")
    return path

@pytest.fixture(scope="session")
def overflow_test_so(fixtures_dir):
    """含溢出漏洞的 SO 路径"""
    path = os.path.join(fixtures_dir, "overflow_test.so")
    if not os.path.exists(path):
        pytest.skip("overflow_test.so not built")
    return path

@pytest.fixture
def mock_jni_signature():
    """模拟 JNI 签名"""
    from src.apk_io.static_analyzer import JNISignature, JNIParam
    return JNISignature(
        java_full_sig="com.test.MediaProcessor.decode(Ljava/lang/String;)[B",
        native_symbol="Java_com_test_MediaProcessor_decode",
        class_name="com.test.MediaProcessor",
        method_name="decode",
        params=[
            JNIParam(java_type="Ljava/lang/String;", native_type="jstring", name="path"),
        ],
        return_type="[B",
        so_path="/fake/libtest.so",
        is_dynamic=False,
    )

@pytest.fixture
def mock_multimedia_func(mock_jni_signature):
    """模拟 MultimediaFuncInfo"""
    from src.llm_interface.querier import MultimediaFuncInfo
    return MultimediaFuncInfo(
        jni_signature=mock_jni_signature,
        is_multimedia=True,
        operation_type="decoding",
        file_format="GIF",
        confidence=0.9,
        raw_responses=["Yes", "decoding", "GIF"],
    )
```

## 4. 按模块的测试用例

### 4.1 config 模块测试

```python
# tests/test_config.py

class TestSettings:
    def test_default_values(self):
        """默认配置值正确"""
        from config.settings import CLANG_PATH, COV_BITMAP_SIZE
        assert "clang" in CLANG_PATH.lower()
        assert COV_BITMAP_SIZE == 65536

    def test_env_override(self, monkeypatch):
        """环境变量覆盖配置"""
        monkeypatch.setenv("OPENAI_API_KEY", "test_key_123")
        from config.settings import load_settings
        settings = load_settings()
        assert settings["LLM_API_KEY"] == "test_key_123"

    def test_path_validation(self, caplog):
        """路径验证"""
        from config.settings import validate_paths
        validate_paths()
        # 不应抛异常，可能有 warning

class TestFormatSkeleton:
    def test_gif_seed_generation(self):
        """GIF 种子生成"""
        from config.file_formats import get_format
        gif = get_format("GIF")
        seed = gif.generate_seed()
        assert seed[:6] == b"GIF89a"
        assert len(seed) >= gif.min_seed_size

    def test_gif_header_validation(self):
        """GIF 头部验证"""
        from config.file_formats import get_format
        gif = get_format("GIF")
        assert gif.validate_header(b"GIF89a" + b"\x00" * 100)
        assert not gif.validate_header(b"PNG\r\n" + b"\x00" * 100)

    def test_unknown_format_raises(self):
        """未知格式抛出 KeyError"""
        from config.file_formats import get_format
        with pytest.raises(KeyError):
            get_format("UNKNOWN_FORMAT")
```

### 4.2 apk_io 模块测试

```python
# tests/test_apk_io.py

class TestSOExtractor:
    def test_extract_from_nonexistent_apk(self):
        """不存在的 APK 抛出 FileNotFoundError"""
        from src.apk_io.extractor import extract_so_files
        with pytest.raises(FileNotFoundError):
            extract_so_files("/nonexistent.apk")

    def test_extract_from_apk_without_so(self, temp_dir):
        """不含 SO 的 APK 返回空列表"""
        # 创建一个不含 lib/ 目录的 zip 文件
        import zipfile
        apk_path = os.path.join(temp_dir, "no_so.apk")
        with zipfile.ZipFile(apk_path, 'w') as z:
            z.writestr("classes.dex", b"fake dex")
        from src.apk_io.extractor import extract_so_files
        result = extract_so_files(apk_path, temp_dir)
        assert result == []

class TestStaticAnalyzer:
    def test_parse_jni_bindings(self, fixtures_dir):
        """JNI 签名解析"""
        # 需要预构建的测试 APK
        pass

class TestSOLoader:
    def test_parse_elf_symbols(self, simple_add_so):
        """ELF 符号解析"""
        from src.apk_io.so_loader import parse_elf_symbols
        symbols = parse_elf_symbols(simple_add_so)
        symbol_names = [s.name for s in symbols]
        assert "add" in symbol_names or any("add" in n for n in symbol_names)

    def test_find_jni_symbols(self, jni_test_so):
        """JNI 符号过滤"""
        from src.apk_io.so_loader import find_jni_symbols
        jni_syms = find_jni_symbols(jni_test_so)
        assert len(jni_syms) > 0
        assert all(s.name.startswith("Java_") for s in jni_syms)
```

### 4.3 llm_interface 模块测试

```python
# tests/test_llm_interface.py

class TestPromptTemplates:
    def test_q1_prompt_building(self, mock_jni_signature):
        """Q1 提示词构建"""
        from src.llm_interface.prompt_templates import build_q1_prompt
        system, user = build_q1_prompt(mock_jni_signature)
        assert "multimedia" in system.lower()
        assert mock_jni_signature.java_full_sig in user

    def test_q2_prompt_building(self, mock_jni_signature):
        """Q2 提示词构建"""
        from src.llm_interface.prompt_templates import build_q2_prompt
        system, user = build_q2_prompt(mock_jni_signature)
        assert "operation" in system.lower()

    def test_q3_prompt_building(self, mock_jni_signature):
        """Q3 提示词构建"""
        from src.llm_interface.prompt_templates import build_q3_prompt
        system, user = build_q3_prompt(mock_jni_signature, "decoding")
        assert "format" in system.lower()

class TestLLMQuerier:
    @pytest.mark.requires_llm
    def test_real_api_call(self, mock_jni_signature):
        """真实 API 调用（需要 API Key）"""
        from src.llm_interface.querier import LLMQuerier
        querier = LLMQuerier()
        is_mm, raw = querier.query_is_multimedia(mock_jni_signature)
        assert isinstance(is_mm, bool)
        assert isinstance(raw, str)

    def test_mock_is_multimedia(self, monkeypatch, mock_jni_signature):
        """Mock: 是多媒体函数"""
        from src.llm_interface.querier import LLMQuerier
        querier = LLMQuerier()
        monkeypatch.setattr(querier, '_call_with_retry', lambda s, u: "Yes")
        is_mm, raw = querier.query_is_multimedia(mock_jni_signature)
        assert is_mm is True

    def test_mock_not_multimedia(self, monkeypatch, mock_jni_signature):
        """Mock: 不是多媒体函数"""
        from src.llm_interface.querier import LLMQuerier
        querier = LLMQuerier()
        monkeypatch.setattr(querier, '_call_with_retry', lambda s, u: "No")
        is_mm, raw = querier.query_is_multimedia(mock_jni_signature)
        assert is_mm is False

    def test_retry_on_rate_limit(self, monkeypatch, mock_jni_signature):
        """速率限制重试"""
        import openai
        from src.llm_interface.querier import LLMQuerier
        querier = LLMQuerier(max_retries=3)

        call_count = 0
        def mock_call(system, user):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise openai.RateLimitError("rate limited", response=None, body=None)
            return "Yes"

        monkeypatch.setattr(querier, '_call_with_retry', mock_call)
        # 需要实际测试 _call_with_retry 的重试逻辑

class TestFilterMultimedia:
    def test_filter_returns_only_multimedia(self, monkeypatch, mock_jni_signature):
        """仅返回多媒体函数"""
        from src.llm_interface.querier import filter_multimedia_functions, LLMQuerier

        querier = LLMQuerier()
        responses = iter(["Yes", "decoding", "GIF", "No"])
        monkeypatch.setattr(querier, '_call_with_retry', lambda s, u: next(responses))

        results = filter_multimedia_functions([mock_jni_signature], querier=querier)
        # 只有 "Yes" 的函数应出现在结果中
```

### 4.4 emulation 模块测试

```python
# tests/test_emulation.py

@pytest.mark.requires_qiling
class TestEmulatedJNIFunc:
    def test_initialize_with_simple_so(self, simple_add_so):
        """加载极简 SO"""
        from src.emulation.qiling_env import EmulatedJNIFunc
        func = EmulatedJNIFunc(simple_add_so, "add")
        func.initialize()
        assert func._func_addr is not None

    def test_call_simple_function(self, simple_add_so):
        """调用极简函数"""
        from src.emulation.qiling_env import EmulatedJNIFunc
        func = EmulatedJNIFunc(simple_add_so, "add")
        func.initialize()
        # 传入两个参数编码后的字节
        result = func.call_function(b"\x02\x00\x00\x00\x03\x00\x00\x00")
        # 结果取决于 add 函数的实现

    def test_jni_stub_not_crash(self, jni_test_so):
        """JNI 桩不崩溃"""
        from src.emulation.qiling_env import EmulatedJNIFunc
        func = EmulatedJNIFunc(jni_test_so, "Java_com_test_NativeLib_process")
        func.initialize()
        # 应不崩溃

    def test_timeout_handling(self, simple_add_so):
        """超时处理"""
        from src.emulation.qiling_env import EmulatedJNIFunc
        func = EmulatedJNIFunc(simple_add_so, "add")
        func.initialize()
        result = func.call_function(b"\x00", timeout_ms=1)
        # 超时后应正常返回，不挂起

    def test_destroy_cleans_up(self, simple_add_so):
        """销毁清理资源"""
        from src.emulation.qiling_env import EmulatedJNIFunc
        func = EmulatedJNIFunc(simple_add_so, "add")
        func.initialize()
        func.destroy()
        assert func.ql is None

class TestDependencyMocker:
    def test_fopen_returns_fd(self, simple_add_so):
        """fopen 返回有效文件描述符"""
        pass  # 需要 Qiling 实例

    def test_android_log_no_crash(self, simple_add_so):
        """__android_log_print 不崩溃"""
        pass
```

### 4.5 fuzzing 模块测试

```python
# tests/test_fuzzing.py

class TestCoverageTracker:
    def test_bitmap_starts_zero(self):
        """初始位图全零"""
        from src.fuzzing.coverage import CoverageTracker
        tracker = CoverageTracker()
        assert all(b == 0 for b in tracker.bitmap)

    def test_coverage_increases(self):
        """覆盖率在执行后增长"""
        from src.fuzzing.coverage import CoverageTracker
        tracker = CoverageTracker()
        # 模拟基本块执行
        class FakeQL:
            pass
        tracker.on_basic_block(FakeQL(), addr=0x1000, size=4)
        assert any(b > 0 for b in tracker.bitmap)

    def test_new_edges_detected(self):
        """新边检测"""
        from src.fuzzing.coverage import CoverageTracker
        tracker = CoverageTracker()
        class FakeQL:
            pass
        prev = bytes(tracker.bitmap)
        tracker.on_basic_block(FakeQL(), addr=0x1000, size=4)
        new = tracker.get_new_edges(prev)
        assert len(new) > 0

class TestFormatAwareMutator:
    def test_raw_mutate_changes_data(self):
        """原始变异改变数据"""
        from src.fuzzing.format_aware import FormatAwareMutator
        mutator = FormatAwareMutator(format_name=None)
        data = bytearray(b"\x00" * 64)
        mutated = mutator._raw_mutate(data, max_size=1024, seed=42)
        assert mutated != data or len(mutated) != len(data)

    def test_gif_magic_preserved(self):
        """GIF 魔数字在变异后保持"""
        from src.fuzzing.format_aware import FormatAwareMutator
        mutator = FormatAwareMutator(format_name="GIF")
        seed = mutator.generate_seed()
        assert seed[:6] == b"GIF89a"
        mutated = mutator.mutate(bytearray(seed), max_size=1048576, seed=42)
        assert mutated[:6] == b"GIF89a"

    def test_generate_seed_with_format(self):
        """格式感知种子生成"""
        from src.fuzzing.format_aware import FormatAwareMutator
        mutator = FormatAwareMutator(format_name="GIF")
        seed = mutator.generate_seed()
        assert seed[:6] == b"GIF89a"

class TestHarnessGeneration:
    def test_generate_source(self):
        """harness 源码生成"""
        from src.fuzzing.harness import generate_harness_source
        src = generate_harness_source("Java_com_test_Foo_bar")
        assert "LLVMFuzzerTestOneInput" in src
        assert "LLVMFuzzerCustomMutator" in src
        assert "__libfuzzer_extra_counters" in src

    @pytest.mark.requires_clang
    def test_compile_harness(self, temp_dir):
        """harness 编译"""
        from src.fuzzing.harness import generate_harness_source, compile_harness
        src = generate_harness_source("test_func")
        output = os.path.join(temp_dir, "libharness.so")
        so_path = compile_harness(src, output)
        assert os.path.exists(so_path)
```

### 4.6 memory_safety 模块测试

```python
# tests/test_memory_safety.py

class TestTagBasedDetector:
    def test_tag_encode_decode(self):
        """标签编码解码"""
        from src.memory_safety.tag_based import TagBasedDetector
        det = TagBasedDetector.__new__(TagBasedDetector)  # 不初始化 Qiling
        addr = 0x12345678
        tag = 0xABCD
        tagged = det.encode_tag(addr, tag)
        assert det.extract_tag(tagged) == tag
        assert det.extract_addr(tagged) == addr

    def test_detect_overflow(self):
        """缓冲区溢出检测"""
        from src.memory_safety.tag_based import TagBasedDetector, MemoryStateTable, MemBlock
        det = TagBasedDetector.__new__(TagBasedDetector)
        det.state_table = MemoryStateTable()
        det._violations = []

        # 创建一个10字节的内存块
        block = MemBlock(
            base_addr=0x1000, size=10, tag=1, freed=False,
            alloc_caller=0, free_caller=0, alloc_time=0, free_time=0,
        )
        det.state_table._blocks[0x1000] = block

        # 检测越界访问
        result = det.check_access(
            ptr=det.encode_tag(0x100A, 1),  # 偏移10，超出范围
            access_size=1,
            access_type="write",
        )
        assert result is not None
        assert result["type"] == "overflow"

    def test_detect_uaf(self):
        """Use-After-Free 检测"""
        from src.memory_safety.tag_based import TagBasedDetector, MemoryStateTable, MemBlock
        det = TagBasedDetector.__new__(TagBasedDetector)
        det.state_table = MemoryStateTable()
        det._violations = []

        # 创建已释放的内存块
        block = MemBlock(
            base_addr=0x2000, size=100, tag=2, freed=True,
            alloc_caller=0, free_caller=0, alloc_time=0, free_time=0,
        )
        det.state_table._blocks[0x2000] = block

        result = det.check_access(
            ptr=det.encode_tag(0x2000, 2),
            access_size=4,
            access_type="read",
        )
        assert result is not None
        assert result["type"] == "uaf"

    def test_detect_double_free(self):
        """双重释放检测"""
        from src.memory_safety.sanitizer_hooks import SanitizerHooks
        # 需要 Qiling 实例，这里测试逻辑层面
        pass

    def test_no_violation_on_valid_access(self):
        """合法访问无违规"""
        from src.memory_safety.tag_based import TagBasedDetector, MemoryStateTable, MemBlock
        det = TagBasedDetector.__new__(TagBasedDetector)
        det.state_table = MemoryStateTable()
        det._violations = []

        block = MemBlock(
            base_addr=0x3000, size=100, tag=3, freed=False,
            alloc_caller=0, free_caller=0, alloc_time=0, free_time=0,
        )
        det.state_table._blocks[0x3000] = block

        result = det.check_access(
            ptr=det.encode_tag(0x3010, 3),  # 合法偏移
            access_size=4,
            access_type="read",
        )
        assert result is None
```

### 4.7 reporter 模块测试

```python
# tests/test_reporter.py

class TestCrashAggregator:
    def test_deduplication(self):
        """崩溃去重"""
        from src.reporter.crash_aggregator import CrashAggregator
        agg = CrashAggregator()
        crash1 = {"crash_hash": "abc123", "type": "crash", "error_message": "test"}
        crash2 = {"crash_hash": "abc123", "type": "crash", "error_message": "test"}
        agg.add_crash(crash1, "func1", "app1")
        agg.add_crash(crash2, "func1", "app1")
        assert len(agg.get_all_crashes()) == 1
        assert agg.get_all_crashes()[0].occurrence_count == 2

    def test_severity_inference(self):
        """严重程度推断"""
        from src.reporter.crash_aggregator import CrashAggregator
        agg = CrashAggregator()
        agg.add_crash({"crash_hash": "1", "type": "overflow"}, "f", "a")
        agg.add_crash({"crash_hash": "2", "type": "uaf"}, "f", "a")
        agg.add_crash({"crash_hash": "3", "type": "timeout"}, "f", "a")
        crashes = agg.get_all_crashes()
        severities = {c.error_type: c.severity for c in crashes}
        assert severities["overflow"] == "critical"
        assert severities["uaf"] == "critical"
        assert severities["timeout"] == "low"

class TestReportGenerator:
    def test_markdown_generation(self, temp_dir):
        """Markdown 报告生成"""
        from src.reporter.report_generator import ReportGenerator, ReportConfig
        from src.reporter.crash_aggregator import CrashAggregator
        config = ReportConfig(output_dir=temp_dir, format="markdown")
        gen = ReportGenerator(config)
        agg = CrashAggregator()
        gen.generate([], agg, {"start_time": 0, "end_time": 1, "total_apks": 0,
                               "total_functions": 0, "total_multimedia_functions": 0,
                               "llm_calls": 0, "llm_cost_usd": 0})
        # 检查报告文件存在
        reports = [f for f in os.listdir(temp_dir) if f.endswith(".md")]
        assert len(reports) > 0

    def test_json_generation(self, temp_dir):
        """JSON 报告生成"""
        import json
        from src.reporter.report_generator import ReportGenerator, ReportConfig
        from src.reporter.crash_aggregator import CrashAggregator
        config = ReportConfig(output_dir=temp_dir, format="json")
        gen = ReportGenerator(config)
        agg = CrashAggregator()
        gen.generate([], agg, {"start_time": 0, "end_time": 1, "total_apks": 0,
                               "total_functions": 0, "total_multimedia_functions": 0,
                               "llm_calls": 0, "llm_cost_usd": 0})
        reports = [f for f in os.listdir(temp_dir) if f.endswith(".json")]
        assert len(reports) > 0
        # 验证 JSON 可解析
        with open(os.path.join(temp_dir, reports[0])) as f:
            data = json.load(f)
        assert "meta" in data
```

## 5. 测试固件构建

### 5.1 极简测试 SO

```c
// tests/fixtures/minimal_apk/jni/native_lib.c

#include <stdint.h>
#include <string.h>

// 极简测试函数
int32_t add(int32_t a, int32_t b) {
    return a + b;
}

// JNI 测试函数
#include <jni.h>

JNIEXPORT jbyteArray JNICALL
Java_com_test_NativeLib_process(JNIEnv *env, jobject thiz, jbyteArray data) {
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);

    // 简单的内存拷贝操作
    jbyte *result = (jbyte *)malloc(len);
    if (result) {
        memcpy(result, bytes, len);
        (*env)->ReleaseByteArrayElements(env, data, bytes, 0);
    }

    jbyteArray output = (*env)->NewByteArray(env, len);
    if (result) {
        (*env)->SetByteArrayRegion(env, output, 0, len, result);
        free(result);
    }
    return output;
}

// 含溢出漏洞的函数
JNIEXPORT void JNICALL
Java_com_test_NativeLib_vulnerable(JNIEnv *env, jobject thiz, jbyteArray data) {
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);

    char buffer[16];
    // CWE-122: 堆缓冲区溢出（如果 len > 16）
    memcpy(buffer, bytes, len);  // Bug!

    (*env)->ReleaseByteArrayElements(env, data, bytes, 0);
}
```

### 5.2 编译脚本

```bash
#!/bin/bash
# tests/fixtures/build_fixtures.sh
# 编译测试固件

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLANG="${CLANG:-clang-18}"

echo "=== Building test fixtures ==="

# 极简 add SO
$CLANG -shared -fPIC -o "$SCRIPT_DIR/simple_add.so" -xc - <<'EOF'
int add(int a, int b) { return a + b; }
EOF

# JNI 测试 SO（需要 jni.h）
$CLANG -shared -fPIC \
    -I"${JAVA_HOME:-/usr/lib/jvm/java-11-openjdk-amd64}/include" \
    -I"${JAVA_HOME:-/usr/lib/jvm/java-11-openjdk-amd64}/include/linux" \
    -o "$SCRIPT_DIR/jni_test.so" \
    "$SCRIPT_DIR/minimal_apk/jni/native_lib.c"

# 溢出漏洞 SO
$CLANG -shared -fPIC -o "$SCRIPT_DIR/overflow_test.so" -xc - <<'EOF'
#include <string.h>
#include <stdlib.h>
int vulnerable_copy(const char *input, int len) {
    char *buf = (char *)malloc(16);
    memcpy(buf, input, len);  // overflow if len > 16
    int result = buf[0];
    free(buf);
    return result;
}
EOF

# UAF 漏洞 SO
$CLANG -shared -fPIC -o "$SCRIPT_DIR/uaf_test.so" -xc - <<'EOF'
#include <stdlib.h>
int use_after_free() {
    int *p = (int *)malloc(sizeof(int));
    *p = 42;
    free(p);
    return *p;  // UAF!
}
EOF

# 双重释放漏洞 SO
$CLANG -shared -fPIC -o "$SCRIPT_DIR/double_free_test.so" -xc - <<'EOF'
#include <stdlib.h>
int double_free() {
    int *p = (int *)malloc(sizeof(int));
    *p = 42;
    free(p);
    free(p);  // Double free!
    return 0;
}
EOF

echo "=== Fixtures built ==="
ls -la "$SCRIPT_DIR"/*.so
```

## 6. 按里程碑的测试计划

### M1: APK I/O + Config

| 测试 | 类型 | 依赖 |
|------|------|------|
| 配置默认值 | unit | 无 |
| 环境变量覆盖 | unit | 无 |
| GIF/JPEG 种子生成 | unit | 无 |
| ELF 符号解析 | unit | simple_add.so |
| APK 解包 | integration | 真实 APK |
| JNI 签名提取 | integration | 真实 APK |
| 100 APK 批量处理 | integration | APK 集合 |

### M2: LLM Interface

| 测试 | 类型 | 依赖 |
|------|------|------|
| 提示词构建 | unit | 无 |
| Mock 是/否分类 | unit | 无 |
| Mock 操作类型识别 | unit | 无 |
| Mock 格式识别 | unit | 无 |
| 重试机制 | unit | 无 |
| 真实 API 调用 | integration | API Key |
| 并发处理 | integration | API Key |
| 标注数据集验证 | e2e | 标注数据 + API Key |

### M3: Emulation

| 测试 | 类型 | 依赖 |
|------|------|------|
| 极简 SO 加载 | integration | Qiling rootfs |
| 函数调用 | integration | Qiling rootfs |
| JNI 桩 | integration | Qiling rootfs |
| 文件 I/O 模拟 | integration | Qiling rootfs |
| 1000 轮稳定性 | slow | Qiling rootfs |

### M4: Fuzzing

| 测试 | 类型 | 依赖 |
|------|------|------|
| 覆盖率追踪 | unit | 无 |
| 格式感知变异 | unit | 无 |
| harness 编译 | integration | Clang |
| 纯 C 模糊测试 | integration | Clang |
| Qiling + 覆盖率集成 | integration | Qiling + Clang |
| CVE-2019-11932 触发 | e2e | WhatsApp SO |

### M5: Memory Safety

| 测试 | 类型 | 依赖 |
|------|------|------|
| 标签编码解码 | unit | 无 |
| 溢出检测 | unit | 无 |
| UAF 检测 | unit | 无 |
| 双重释放检测 | unit | 无 |
| Juliet CWE-122 | integration | 漏洞 SO |
| Juliet CWE-415 | integration | 漏洞 SO |
| Juliet CWE-416 | integration | 漏洞 SO |
| 性能开销 | slow | Qiling |

### M6: Pipeline + Reporter

| 测试 | 类型 | 依赖 |
|------|------|------|
| 崩溃去重 | unit | 无 |
| 报告生成 | unit | 无 |
| 空目录处理 | integration | 无 |
| 单 APK 端到端 | e2e | APK + Qiling + Clang |
| 断点续传 | integration | 无 |
| 500 APK 大规模 | slow | APK 集合 + 全部依赖 |

## 7. CI 配置

```yaml
# .github/workflows/test.yml (示例)

name: Tests
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Build fixtures
        run: bash tests/fixtures/build_fixtures.sh
      - name: Run unit tests
        run: pytest -m "unit" --cov=src --cov-report=xml

  integration-tests:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest
      - name: Build fixtures
        run: bash tests/fixtures/build_fixtures.sh
      - name: Run integration tests
        run: pytest -m "integration" --timeout=300

  # e2e tests 需要 Qiling rootfs 和 API Key，仅在手动触发时运行
```

## 8. 测试运行命令

```bash
# 所有单元测试
pytest -m "unit" -v

# 所有集成测试
pytest -m "integration" -v

# 特定模块
pytest tests/test_config.py -v
pytest tests/test_apk_io.py -v

# 跳过需要外部依赖的测试
pytest -m "not requires_llm and not requires_qiling" -v

# 带覆盖率
pytest --cov=src --cov-report=html -v

# 慢速测试
pytest -m "slow" -v --timeout=600
```
