# config 模块开发文档

## 1. 模块职责

集中管理项目所有配置项，包括：
- LLVM/LibFuzzer 工具链路径
- Qiling 模拟环境参数
- APK/SO 文件路径
- LLM API 配置
- 模糊测试参数（覆盖率位图大小、超时、轮次）
- 文件格式骨架定义

## 2. 文件结构

```
config/
├── __init__.py          # 导出 settings 中所有配置项
├── settings.py          # 全局配置（路径、参数、开关）
└── file_formats/        # 文件格式骨架定义
    ├── __init__.py      # 格式注册表
    ├── gif.py           # GIF 文件格式骨架
    ├── jpeg.py          # JPEG 文件格式骨架
    └── webp.py          # WebP 文件格式骨架
```

## 3. settings.py 详细规格

### 3.1 配置项清单

```python
# === LLVM / LibFuzzer ===
CLANG_PATH: str               # Clang 可执行文件路径，默认 "/usr/bin/clang-18"
LIBCLANG_RT_PATH: str         # Clang 运行时库路径
LIBFUZZER_TIMEOUT: int        # 单函数模糊测试超时秒数，默认 300
LIBFUZZER_MAX_RUNS: int       # 单函数最大变异轮次，默认 100000

# === Qiling 模拟环境 ===
QL_ROOTFS_PATH: str           # Android rootfs 路径
QL_ARCH: str                  # 目标架构，默认 "arm64"
QL_OS: str                    # 目标操作系统，默认 "linux"
QL_VERBOSE: int               # Qiling 日志级别 (0-4)，默认 0
QL_TIMEOUT: int               # 单次模拟执行超时毫秒数，默认 5000

# === APK / SO 路径 ===
APK_INPUT_DIR: str            # 输入 APK 目录
SO_OUTPUT_DIR: str            # 提取的 SO 输出目录

# === LLM ===
LLM_MODEL_NAME: str           # 模型名，默认 "gpt-4o"
LLM_API_KEY: str              # 从 OPENAI_API_KEY 环境变量读取
LLM_API_BASE: str             # API base URL，默认 OpenAI 官方
LLM_MAX_RETRIES: int          # 最大重试次数，默认 3
LLM_RETRY_DELAY: float        # 重试间隔秒，默认 1.0
LLM_TEMPERATURE: float        # 生成温度，默认 0.0（确定性输出）

# === 覆盖率 ===
COV_BITMAP_SIZE: int          # 覆盖率位图大小，默认 65536

# === 内存安全检测 ===
MEM_SAFETY_ENABLED: bool      # 是否启用主动内存检测，默认 True
MEM_TAG_BITS: int             # 标记指针使用的位数，默认 16

# === 输出 ===
OUTPUT_BASE_DIR: str          # 输出根目录，默认 "output/"
```

### 3.2 配置加载策略

```python
def load_settings() -> dict:
    """
    加载配置，优先级：环境变量 > .env 文件 > 默认值。
    所有路径在加载时转为绝对路径。
    关键路径（CLANG_PATH, QL_ROOTFS_PATH）在加载时验证存在性，
    不存在则发出 warning 但不中断（允许延迟安装工具链）。
    """
```

### 3.3 实现步骤

1. 定义所有配置项为模块级常量，带默认值
2. 实现 `load_settings()` 从 `.env` 文件和环境变量覆盖默认值
3. 实现路径验证函数 `validate_paths()`，检查关键路径是否存在
4. 在 `__init__.py` 中统一导出，确保 `from config import CLANG_PATH` 可用

## 4. file_formats 格式骨架详细规格

### 4.1 格式注册表 (`file_formats/__init__.py`)

```python
# 格式名 -> 格式模块的映射
FORMAT_REGISTRY: dict[str, FormatSkeleton] = {}

def get_format(name: str) -> FormatSkeleton:
    """根据格式名返回骨架定义，不存在则 raise KeyError"""

def register_format(name: str, skeleton: FormatSkeleton) -> None:
    """注册新格式骨架"""
```

### 4.2 FormatSkeleton 数据结构

```python
@dataclass
class FieldDef:
    name: str               # 字段名，如 "magic", "width"
    offset: int             # 相对于结构起点的偏移（字节）
    size: int               # 字段大小（字节）
    fixed: bool             # True=变异时保持不变，False=可变异
    default_value: bytes    # 默认字节值
    description: str        # 人类可读描述

@dataclass
class FormatSkeleton:
    name: str                  # 格式名，如 "GIF"
    magic: bytes               # 魔数字节，如 b"GIF89a"
    fields: list[FieldDef]     # 结构化字段列表
    max_seed_size: int         # 建议的最大种子大小（字节）
    min_seed_size: int         # 建议的最小种子大小（字节）

    def generate_seed(self) -> bytes:
        """根据骨架生成一个合法的种子文件（所有字段填入默认值）"""

    def validate_header(self, data: bytes) -> bool:
        """检查 data 的头部是否符合格式骨架"""
```

### 4.3 GIF 骨架示例 (`file_formats/gif.py`)

```python
GIF_SKELETON = FormatSkeleton(
    name="GIF",
    magic=b"GIF89a",
    fields=[
        FieldDef("signature",   offset=0, size=6, fixed=True,  default_value=b"GIF89a",  description="GIF签名"),
        FieldDef("width",       offset=6, size=2, fixed=False, default_value=b"\x0A\x00", description="逻辑屏幕宽度"),
        FieldDef("height",      offset=8, size=2, fixed=False, default_value=b"\x0A\x00", description="逻辑屏幕高度"),
        FieldDef("packed",      offset=10,size=1, fixed=False, default_value=b"\x70",     description="全局颜色表标志+分辨率"),
        FieldDef("bg_color",    offset=11,size=1, fixed=False, default_value=b"\x00",     description="背景色索引"),
        FieldDef("aspect",      offset=12,size=1, fixed=False, default_value=b"\x00",     description="像素宽高比"),
        FieldDef("gct",         offset=13,size=768,fixed=False,default_value=b"\x00"*768, description="全局颜色表(256*3)"),
        FieldDef("img_desc",    offset=781,size=11,fixed=True, default_value=b"\x2c\x00\x00\x00\x00\x0a\x00\x0a\x00\x00\x00",
                 description="图像描述符"),
        FieldDef("lzw_min",     offset=792,size=1, fixed=False, default_value=b"\x08",    description="LZW最小码大小"),
        FieldDef("img_data",    offset=793,size=10,fixed=False,default_value=b"\x08\x01\x00\x00\x01\x00\x00\x3b\x00\x00",
                 description="图像数据块+GIF结尾"),
    ],
    max_seed_size=1048576,  # 1MB
    min_seed_size=796,
)
```

### 4.4 JPEG / WebP 骨架

按照同样模式定义 `JPEG_SKELETON` 和 `WEBP_SKELETON`，关键字段（SOI marker `0xFFD8`、APP0 marker 等）设为 `fixed=True`。

### 4.5 实现步骤

1. 定义 `FieldDef` 和 `FormatSkeleton` 数据类
2. 实现 `generate_seed()` 和 `validate_header()` 方法
3. 编写 GIF、JPEG、WebP 三个骨架定义
4. 实现注册表和 `get_format()` / `register_format()`
5. 在 `__init__.py` 中自动注册所有内置格式

## 5. 跨模块依赖

- **apk_io**: 读取 `APK_INPUT_DIR`, `SO_OUTPUT_DIR`
- **llm_interface**: 读取 `LLM_*` 系列配置
- **emulation**: 读取 `QL_*` 系列配置
- **fuzzing**: 读取 `CLANG_PATH`, `LIBFUZZER_*`, `COV_BITMAP_SIZE`；使用 `file_formats` 生成种子
- **memory_safety**: 读取 `MEM_SAFETY_ENABLED`, `MEM_TAG_BITS`
- **reporter**: 读取 `OUTPUT_BASE_DIR`

## 6. 错误处理

- 关键路径不存在：`logging.warning()` 提示，不中断程序（允许延迟安装）
- `.env` 文件不存在：静默跳过，使用默认值
- 环境变量格式错误：`logging.warning()` 并回退到默认值
- 格式名未注册：`raise KeyError(f"Format '{name}' not registered")`

## 7. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| 默认配置加载 | 调用 `load_settings()` 无 .env 无环境变量 | 所有值匹配默认值 |
| 环境变量覆盖 | 设置 `OPENAI_API_KEY=test` | `LLM_API_KEY == "test"` |
| .env 文件加载 | 创建 `.env` 文件 | 正确解析并覆盖 |
| 路径验证 | 删除 Clang 后调用 `validate_paths()` | 发出 warning |
| GIF 种子生成 | `GIF_SKELETON.generate_seed()` | 返回字节串以 `GIF89a` 开头 |
| GIF 头部验证 | `GIF_SKELETON.validate_header(valid_gif)` | 返回 True |
| GIF 头部验证 | `GIF_SKELETON.validate_header(b"PNG...")` | 返回 False |
| 格式注册表 | `get_format("GIF")` | 返回 GIF_SKELETON |
| 格式注册表 | `get_format("UNKNOWN")` | raise KeyError |
