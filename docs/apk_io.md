# apk_io 模块开发文档

## 1. 模块职责

从 APK 文件中提取原生库（.so）和 JNI 函数签名信息。输出每个 APK 内所有 JNI 函数的结构化签名列表，供下游 LLM 模块筛选。

## 2. 文件结构

```
src/apk_io/
├── __init__.py          # 导出 extract_so_files, parse_jni_bindings, extract_all
├── extractor.py         # APK 解包、SO 库提取
├── static_analyzer.py   # 提取 JNI 函数签名
└── so_loader.py         # 解析 ELF 符号表
```

## 3. 详细接口规格

### 3.1 extractor.py

```python
def extract_so_files(apk_path: str, output_dir: str | None = None) -> list[str]:
    """
    解包 APK 并提取所有 .so 文件。

    Args:
        apk_path: APK 文件绝对路径
        output_dir: SO 输出目录，默认使用 config.SO_OUTPUT_DIR

    Returns:
        提取出的 .so 文件绝对路径列表

    Raises:
        FileNotFoundError: apk_path 不存在
        ValueError: 文件不是有效 APK

    Implementation:
        1. 验证 APK 存在且为 zip 格式
        2. 使用 zipfile 或 androguard 解包
        3. 在 output_dir 下创建以 APK 包名命名的子目录
        4. 提取 lib/<abi>/*.so 到子目录
        5. 记录提取日志（APK路径、SO数量、SO名称列表）
        6. 返回所有提取的 .so 绝对路径列表
    """
```

**关键实现细节**：
- APK 本质是 zip 文件，原生库位于 `lib/<abi>/` 子目录（abi 可为 armeabi-v7a, arm64-v8a, x86, x86_64）
- 优先提取 arm64-v8a 架构的 SO（与 Qiling 配置匹配）
- 如果 APK 不含原生库，返回空列表而非报错

```python
def get_apk_package_name(apk_path: str) -> str:
    """
    从 APK 中读取包名（AndroidManifest.xml 中的 package 属性）。

    使用 androguard 的 APK 类解析。

    Returns:
        包名字符串，如 "com.example.app"
    """
```

### 3.2 static_analyzer.py

```python
@dataclass
class JNIParam:
    java_type: str       # Java 类型签名，如 "Ljava/lang/String;"
    native_type: str     # 推断的 C 类型，如 "jstring"
    name: str            # 参数名（从调试信息推断，不可得时为 "arg0", "arg1", ...）

@dataclass
class JNISignature:
    java_full_sig: str       # 完整 Java 签名，如 "com.example.MediaProcessor.decode(Ljava/lang/String;)[B"
    native_symbol: str       # JNI 函数符号名，如 "Java_com_example_MediaProcessor_decode"
    class_name: str          # Java 类名
    method_name: str         # Java 方法名
    params: list[JNIParam]   # 参数列表
    return_type: str         # 返回类型签名
    so_path: str             # 所属 SO 文件路径
    is_dynamic: bool         # 是否通过 RegisterNatives 动态注册

def parse_jni_bindings(so_path: str, apk_path: str) -> list[JNISignature]:
    """
    分析 JNI 绑定，提取函数签名。

    策略：
    1. 静态绑定：匹配 Java_ 前缀的导出符号
    2. 动态绑定：分析 .init_array 和 JNI_OnLoad 中的 RegisterNatives 调用（M1阶段可暂不实现）

    Args:
        so_path: .so 文件绝对路径
        apk_path: 原始 APK 路径（用于解析 DEX 中的 native 声明）

    Returns:
        JNISignature 列表

    Implementation:
        1. 使用 so_loader 解析 SO 导出符号表，过滤 Java_* 前缀
        2. 使用 androguard 解析 APK 的 classes.dex，提取所有 native 方法
        3. 将 Java native 方法与 SO 符号进行匹配：
           - 静态注册：类名+方法名编码为 Java_<包>_<类>_<方法> 格式
           - 对每个匹配项，解析参数和返回类型签名
        4. 返回匹配成功的 JNISignature 列表
    """
```

**JNI 签名编码规则**（必须严格遵循）：
- 包名分隔符 `.` → `_`
- 嵌套类分隔符 `$` → `_00024`
- 方法名中 `_` → `_1`
- 例如：`org.example.Foo.bar(String)` → `Java_org_example_Foo_bar`

```python
def parse_dex_native_methods(apk_path: str) -> list[dict]:
    """
    从 DEX 文件中提取所有 native 方法声明。

    使用 androguard 的 DalvikVMAnalysis：
    - 遍历所有类和方法的 modifier
    - 筛选 access_flags 包含 ACC_NATIVE 的方法

    Returns:
        [{"class": "com.example.MediaProcessor",
          "method": "decode",
          "descriptor": "(Ljava/lang/String;)[B"}, ...]
    """
```

### 3.3 so_loader.py

```python
@dataclass
class ELFSymbol:
    name: str           # 符号名
    address: int        # 虚拟地址
    size: int           # 符号大小
    type: str           # 符号类型 (FUNC, OBJECT, ...)

def parse_elf_symbols(so_path: str) -> list[ELFSymbol]:
    """
    解析 ELF 动态符号表（.dynsym）。

    使用 pyelftools 或手动解析 ELF header：
    1. 读取 ELF header，定位 .dynsym section
    2. 解析每个符号条目
    3. 过滤 STT_FUNC 类型（函数符号）
    4. 返回符号列表

    注意：ARM64 SO 是 little-endian ELF64 格式
    """
```

```python
def find_jni_symbols(so_path: str) -> list[ELFSymbol]:
    """
    过滤出 JNI 函数符号（以 Java_ 开头）。

    Returns:
        仅包含 JNI 函数的 ELFSymbol 列表
    """
```

```python
def find_init_array(so_path: str) -> list[int]:
    """
    解析 .init_array 段，提取初始化函数地址列表。
    用于后续动态注册分析（M2+ 阶段）。

    Returns:
        函数地址列表
    """
```

### 3.4 顶层编排函数

```python
def extract_all(apk_paths: list[str], output_dir: str | None = None) -> dict[str, list[JNISignature]]:
    """
    批量处理 APK 列表，提取所有 JNI 签名。

    Args:
        apk_paths: APK 文件路径列表
        output_dir: SO 输出目录

    Returns:
        {apk_path: [JNISignature, ...]} 映射

    Implementation:
        1. 遍历 apk_paths
        2. 对每个 APK 调用 extract_so_files()
        3. 对每个 SO 调用 parse_jni_bindings()
        4. 汇总返回
    """
```

## 4. 关键实现细节

### 4.1 Androguard 使用方式

```python
from androguard.core.apk import APK
from androguard.core.dex import DEX

apk = APK(apk_path)
package_name = apk.get_package()

# 获取所有 DEX
for dex in apk.get_all_dex():
    d = DEX(dex)
    for cls in d.get_classes():
        for method in cls.get_methods():
            if method.get_access_flags_string() 包含 "native":
                # 提取签名
```

### 4.2 ELF 解析选择

- **优先使用 pyelftools**：`pip install pyelftools`，API 稳定，支持 ELF64
- 如果 pyelftools 不可用，可使用 `subprocess` 调用 `readelf -Ws` 解析输出

### 4.3 JNI 签名解码

Java 类型签名到 C/Native 类型的映射表：

| Java 签名 | C 类型 |
|-----------|--------|
| Z | jboolean |
| B | jbyte |
| C | jchar |
| S | jshort |
| I | jint |
| J | jlong |
| F | jfloat |
| D | jdouble |
| L...; | jobject (具体类型) |
| [ | jarray (元素类型数组) |

## 5. 跨模块依赖

- **依赖**: `config.settings` (APK_INPUT_DIR, SO_OUTPUT_DIR)
- **被依赖**: `llm_interface` (消费 JNISignature 列表), `emulation` (使用 SO 路径加载)

## 6. 错误处理

| 异常场景 | 处理方式 |
|---------|---------|
| APK 文件不存在 | raise FileNotFoundError |
| APK 格式损坏 | raise ValueError("Invalid APK format") |
| SO 无导出符号 | 返回空列表，logging.warning |
| DEX 解析失败 | 跳过该 DEX，logging.warning，继续处理其他 DEX |
| ELF 解析失败 | 跳过该 SO，logging.warning |
| 输出目录不存在 | 自动创建 |

## 7. 实现步骤

1. **Step 1**: 实现 `so_loader.py` — ELF 符号解析，单元测试使用真实 SO
2. **Step 2**: 实现 `extractor.py` — APK 解包和 SO 提取
3. **Step 3**: 实现 `static_analyzer.py` — DEX 解析和签名匹配
4. **Step 4**: 实现顶层 `extract_all()` 编排函数
5. **Step 5**: 使用 `tests/fixtures/` 下的极简 APK 进行端到端测试
6. **Step 6**: 使用真实 APK（如 Telegram）进行验证

## 8. 测试计划

| 测试项 | 输入 | 预期输出 |
|--------|------|---------|
| 空APK（无SO） | 不含原生库的 APK | 返回空列表 |
| 单SO单JNI函数 | 极简测试 APK | 正确提取1个 JNISignature |
| 多ABI | 包含 arm64 + x86 的 APK | 优先提取 arm64 |
| 签名匹配准确性 | 已知JNI函数的 APK | java_full_sig 与 native_symbol 对应正确 |
| 参数解析 | 带多个参数的 JNI 函数 | params 列表完整且类型正确 |
| 批量处理 | 5个 APK | 全部成功提取，无异常 |
| 大型APK | 微信/Telegram APK | 不崩溃，提取结果合理 |
