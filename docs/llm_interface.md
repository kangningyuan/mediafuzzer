# llm_interface 模块开发文档

## 1. 模块职责

基于 JNI 函数签名，通过自启发式多轮问询（Self-Heuristic Inquiry）调用 LLM，判断函数是否为多媒体处理函数，并识别操作类型和目标文件格式。

## 2. 文件结构

```
src/llm_interface/
├── __init__.py           # 导出 filter_multimedia_functions, MultimediaFuncInfo
├── prompt_templates.py   # 自启发式提示词模板
└── querier.py            # LLM API 调用、重试、结果解析
```

## 3. 数据结构

```python
@dataclass
class MultimediaFuncInfo:
    """LLM 筛选出的多媒体函数信息"""
    jni_signature: JNISignature    # 来自 apk_io 的原始签名
    is_multimedia: bool            # 是否为多媒体函数
    operation_type: str            # 操作类型：decoding / encoding / rendering / clipping / conversion / other
    file_format: str               # 目标文件格式：GIF / JPEG / WebP / PNG / MP4 / unknown
    confidence: float              # LLM 返回的置信度 (0.0-1.0)，用于排序
    raw_responses: list[str]       # 原始 LLM 响应，用于调试和审计
```

## 4. 详细接口规格

### 4.1 prompt_templates.py

实现论文图2的三轮对话逻辑：

```python
# 第一轮：二分类判断
Q1_SYSTEM = """You are an expert in Android multimedia frameworks.
Analyze the given JNI function signature and determine if it involves
multimedia processing (image, video, audio codec, editing, conversion,
rendering, or any media-related operation).
Answer ONLY 'Yes' or 'No'."""

Q1_USER_TEMPLATE = """Signature: {java_full_sig}
Native symbol: {native_symbol}
Return type: {return_type}
Parameters: {params_str}

Does this function involve multimedia processing? Answer 'Yes' or 'No' only."""

# 第二轮：操作类型识别（仅在第一轮回答 Yes 时执行）
Q2_SYSTEM = """You identified a function as multimedia-related.
Now classify the specific multimedia operation it performs.
Choose from: decoding, encoding, rendering, clipping, conversion, mixing, other.
Respond with exactly one word."""

Q2_USER_TEMPLATE = """Signature: {java_full_sig}
Native symbol: {native_symbol}

What specific multimedia operation does this function perform?"""

# 第三轮：文件格式识别（仅在第一轮回答 Yes 时执行）
Q3_SYSTEM = """You identified a multimedia function.
Determine the target file format it processes.
Common formats: GIF, JPEG, PNG, WebP, BMP, TIFF, MP4, AVI, MKV, MP3, AAC, OGG, FLAC.
If unclear, respond 'unknown'.
Respond with the format name only (uppercase)."""

Q3_USER_TEMPLATE = """Signature: {java_full_sig}
Native symbol: {native_symbol}
Operation: {operation_type}

What target file format does this function process?"""
```

**提示词设计要点**：
- System prompt 设定角色和约束，确保输出格式稳定
- User prompt 包含完整签名信息，给 LLM 充分上下文
- 每轮对话独立（非上下文连续），避免前一轮错误传播
- 使用 `temperature=0.0` 确保输出确定性

```python
def build_q1_prompt(sig: JNISignature) -> tuple[str, str]:
    """构建第一轮问询的 (system, user) prompt"""
    params_str = ", ".join(f"{p.java_type} {p.name}" for p in sig.params)
    return Q1_SYSTEM, Q1_USER_TEMPLATE.format(
        java_full_sig=sig.java_full_sig,
        native_symbol=sig.native_symbol,
        return_type=sig.return_type,
        params_str=params_str or "void",
    )

def build_q2_prompt(sig: JNISignature) -> tuple[str, str]:
    """构建第二轮问询的 (system, user) prompt"""
    return Q2_SYSTEM, Q2_USER_TEMPLATE.format(
        java_full_sig=sig.java_full_sig,
        native_symbol=sig.native_symbol,
    )

def build_q3_prompt(sig: JNISignature, operation_type: str) -> tuple[str, str]:
    """构建第三轮问询的 (system, user) prompt"""
    return Q3_SYSTEM, Q3_USER_TEMPLATE.format(
        java_full_sig=sig.java_full_sig,
        native_symbol=sig.native_symbol,
        operation_type=operation_type,
    )
```

### 4.2 querier.py

```python
class LLMQuerier:
    """LLM API 客户端，封装调用、重试和结果解析"""

    def __init__(self, model: str | None = None, api_key: str | None = None,
                 api_base: str | None = None, max_retries: int | None = None):
        """
        初始化 OpenAI 客户端。
        参数默认值从 config.settings 读取。
        """
        self.client = openai.OpenAI(
            api_key=api_key or settings.LLM_API_KEY,
            base_url=api_base or settings.LLM_API_BASE,
        )
        self.model = model or settings.LLM_MODEL_NAME
        self.max_retries = max_retries or settings.LLM_MAX_RETRIES

    def _call_with_retry(self, system: str, user: str) -> str:
        """
        带重试的 API 调用。

        重试策略：指数退避 (1s, 2s, 4s)
        可重试异常：openai.RateLimitError, openai.APITimeoutError, openai.APIConnectionError
        不可重试：openai.AuthenticationError, openai.BadRequestError
        """
        for attempt in range(self.max_retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=settings.LLM_TEMPERATURE,
                    max_tokens=10,  # 预期回答极短
                )
                return resp.choices[0].message.content.strip()
            except openai.RateLimitError:
                delay = settings.LLM_RETRY_DELAY * (2 ** attempt)
                logging.warning(f"Rate limited, retrying in {delay}s...")
                time.sleep(delay)
            except (openai.AuthenticationError, openai.BadRequestError) as e:
                logging.error(f"Non-retryable API error: {e}")
                raise
        raise RuntimeError(f"LLM API call failed after {self.max_retries} retries")

    def query_is_multimedia(self, sig: JNISignature) -> tuple[bool, str]:
        """
        第一轮问询：是否为多媒体函数。

        Returns:
            (is_multimedia, raw_response)
        """
        system, user = build_q1_prompt(sig)
        response = self._call_with_retry(system, user)
        return response.lower().startswith("yes"), response

    def query_operation_type(self, sig: JNISignature) -> str:
        """
        第二轮问询：操作类型。
        返回值标准化为小写。
        """
        system, user = build_q2_prompt(sig)
        response = self._call_with_retry(system, user)
        op = response.strip().lower()
        valid_ops = {"decoding", "encoding", "rendering", "clipping", "conversion", "mixing", "other"}
        return op if op in valid_ops else "other"

    def query_file_format(self, sig: JNISignature, operation_type: str) -> str:
        """
        第三轮问询：文件格式。
        返回值标准化为大写。
        """
        system, user = build_q3_prompt(sig, operation_type)
        response = self._call_with_retry(system, user)
        fmt = response.strip().upper()
        return fmt

    def analyze_function(self, sig: JNISignature) -> MultimediaFuncInfo:
        """
        对单个 JNI 签名执行完整的三轮问询流水线。

        Implementation:
        1. 调用 query_is_multimedia()
        2. 如果返回 False，直接返回 is_multimedia=False 的结果
        3. 如果返回 True，依次调用 query_operation_type() 和 query_file_format()
        4. 组装 MultimediaFuncInfo 返回
        """
        is_mm, q1_resp = self.query_is_multimedia(sig)
        raw_responses = [q1_resp]
        op_type = "unknown"
        fmt = "unknown"
        confidence = 0.5

        if is_mm:
            op_type = self.query_operation_type(sig)
            raw_responses.append(op_type)
            fmt = self.query_file_format(sig, op_type)
            raw_responses.append(fmt)
            confidence = 0.8  # LLM 确认时的基础置信度

        return MultimediaFuncInfo(
            jni_signature=sig,
            is_multimedia=is_mm,
            operation_type=op_type,
            file_format=fmt,
            confidence=confidence,
            raw_responses=raw_responses,
        )
```

```python
def filter_multimedia_functions(
    signatures: list[JNISignature],
    querier: LLMQuerier | None = None,
    concurrency: int = 4,
) -> list[MultimediaFuncInfo]:
    """
    批量筛选多媒体函数。

    使用 ThreadPoolExecutor 并发调用 LLM，加速处理。

    Args:
        signatures: 来自 apk_io 的 JNI 签名列表
        querier: LLM 客户端实例，默认创建新实例
        concurrency: 并发数，默认 4（受 API 速率限制约束）

    Returns:
        仅包含 is_multimedia=True 的 MultimediaFuncInfo 列表，
        按置信度降序排列
    """
    if querier is None:
        querier = LLMQuerier()

    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(querier.analyze_function, sig): sig for sig in signatures}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                sig = futures[future]
                logging.error(f"Failed to analyze {sig.java_full_sig}: {e}")

    # 过滤并排序
    multimedia = [r for r in results if r.is_multimedia]
    multimedia.sort(key=lambda x: x.confidence, reverse=True)
    return multimedia
```

## 5. 关键实现细节

### 5.1 自启发式问询流程

```
JNI签名
  │
  ▼
  Q1: 是否多媒体? ──No──▶ 丢弃
  │
  Yes
  │
  ▼
  Q2: 操作类型? ──▶ decoding / encoding / ...
  │
  ▼
  Q3: 文件格式? ──▶ GIF / JPEG / WebP / ...
  │
  ▼
  MultimediaFuncInfo
```

### 5.2 启发式快速过滤（可选优化）

在调用 LLM 前可加入关键词预过滤，减少 API 调用量：

```python
MULTIMEDIA_KEYWORDS = {
    "decode", "encode", "render", "compress", "decompress",
    "bitmap", "image", "video", "audio", "codec", "pixel",
    "frame", "gif", "jpeg", "jpg", "png", "webp", "bmp",
    "mp4", "mp3", "aac", "media", "thumbnail", "crop",
    "scale", "rotate", "transform", "filter", "blend",
}

def heuristic_prefilter(sig: JNISignature) -> bool | None:
    """
    基于关键词的快速预过滤。
    Returns:
        True  -> 明确是多媒体，可跳过 LLM 调用
        False -> 明确不是，可跳过 LLM 调用
        None  -> 不确定，需要 LLM 判断
    """
    sig_lower = sig.java_full_sig.lower()
    for kw in MULTIMEDIA_KEYWORDS:
        if kw in sig_lower:
            return True
    # 如果签名包含明确的非多媒体标识（如 database, network, crypto）
    NON_MEDIA_KEYWORDS = {"database", "sql", "network", "socket", "crypto", "encrypt", "decrypt", "auth", "login"}
    for kw in NON_MEDIA_KEYWORDS:
        if kw in sig_lower:
            return False
    return None
```

### 5.3 API 调用审计日志

每次 LLM 调用应记录到 `output/<timestamp>/llm_audit.jsonl`：

```json
{
    "timestamp": "2026-05-04T10:30:00Z",
    "function_sig": "com.example.MediaProcessor.decode",
    "round": 1,
    "system_prompt_hash": "sha256:...",
    "user_prompt": "...",
    "response": "Yes",
    "model": "gpt-4o",
    "latency_ms": 832,
    "token_usage": {"prompt": 85, "completion": 1, "total": 86}
}
```

## 6. 跨模块依赖

- **依赖**: `config.settings` (LLM_* 配置), `apk_io` (JNISignature 类型)
- **被依赖**: `fuzzing` (消费 MultimediaFuncInfo 列表，用于选择变异策略和种子格式)

## 7. 错误处理

| 异常场景 | 处理方式 |
|---------|---------|
| API Key 无效 | raise，终止流水线 |
| 速率限制 | 指数退避重试，最多3次 |
| 网络超时 | 重试 |
| 响应格式不符合预期 | 尝试解析，失败则标记为 "unknown"，不中断 |
| 并发调用部分失败 | 跳过失败的函数，记录错误日志 |
| API 额度耗尽 | 记录已处理结果，raise 提示剩余未处理 |

## 8. 实现步骤

1. **Step 1**: 实现 `prompt_templates.py`，定义三轮对话模板和构建函数
2. **Step 2**: 实现 `LLMQuerier._call_with_retry()`，验证 API 连通性
3. **Step 3**: 实现三轮问询方法 `query_is_multimedia`, `query_operation_type`, `query_file_format`
4. **Step 4**: 实现 `analyze_function()` 完整流水线
5. **Step 5**: 实现批量 `filter_multimedia_functions()`，含并发和错误处理
6. **Step 6**: （可选）实现启发式预过滤
7. **Step 7**: 实现审计日志

## 9. 测试计划

| 测试项 | 方法 | 预期结果 |
|--------|------|---------|
| Q1 解析 - Yes | 模拟 LLM 返回 "Yes" | is_multimedia=True |
| Q1 解析 - No | 模拟 LLM 返回 "No" | is_multimedia=False |
| Q1 解析 - 模糊回答 | 模拟 LLM 返回 "It appears so" | is_multimedia=True (宽松匹配) |
| Q2 操作类型标准化 | 返回 "Decoding" | op_type="decoding" |
| Q2 未知操作类型 | 返回 "quantization" | op_type="other" |
| Q3 格式标准化 | 返回 "gif" | fmt="GIF" |
| 重试机制 | Mock API 前两次 RateLimitError | 第三次成功，无异常 |
| 不可重试异常 | Mock AuthenticationError | 直接 raise |
| 并发处理 | 10个签名，4并发 | 全部完成，无异常 |
| 部分失败 | 1个签名触发异常 | 跳过该签名，其余正常 |
| 端到端验证 | 论文表3标注数据集 | 召回率 > 90%, 精确率 > 80% |
| 审计日志 | 执行分析后检查日志文件 | JSONL 格式正确，字段完整 |
