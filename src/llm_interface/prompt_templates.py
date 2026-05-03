"""Self-heuristic inquiry prompt templates for LLM multimedia function filtering."""

Q1_SYSTEM = (
    "You are an expert in Android native development and multimedia processing. "
    "Your task is to determine whether a given JNI function signature is related "
    "to multimedia processing. Answer with only 'Yes' or 'No'."
)

Q1_USER = (
    "Analyze the following JNI function signature and determine if it involves "
    "multimedia processing (e.g., image, video, audio codec, editing, conversion, "
    "rendering, mixing). Answer 'Yes' or 'No' only.\n\n"
    "Signature: {signature}"
)

Q2_SYSTEM = (
    "You are an expert in multimedia processing operations. "
    "Classify the multimedia operation type of the given function. "
    "Respond with exactly one of: decoding, encoding, rendering, clipping, "
    "conversion, mixing, other."
)

Q2_USER = (
    "What specific multimedia operation does this function perform? "
    "Choose from: decoding, encoding, rendering, clipping, conversion, mixing, other.\n\n"
    "Signature: {signature}"
)

Q3_SYSTEM = (
    "You are an expert in multimedia file formats. "
    "Identify the target file format that this multimedia function processes. "
    "Respond with a format name (GIF, JPEG, PNG, WebP, MP4, AVI, MKV, FLAC, "
    "MP3, AAC, OGG, WAV, BMP, TIFF) or UNKNOWN if unclear."
)

Q3_USER = (
    "What target file format does this function process? "
    "Answer with a single format name (e.g., GIF, JPEG, PNG, WebP, MP4) or UNKNOWN.\n\n"
    "Signature: {signature}\n"
    "Operation type: {operation_type}"
)


def build_q1_prompt(signature: str) -> tuple[str, str]:
    """Build Round 1 prompt: Is this function multimedia-related?"""
    return Q1_SYSTEM, Q1_USER.format(signature=signature)


def build_q2_prompt(signature: str) -> tuple[str, str]:
    """Build Round 2 prompt: What operation type?"""
    return Q2_SYSTEM, Q2_USER.format(signature=signature)


def build_q3_prompt(signature: str, operation_type: str) -> tuple[str, str]:
    """Build Round 3 prompt: What target file format?"""
    return Q3_SYSTEM, Q3_USER.format(
        signature=signature, operation_type=operation_type,
    )
