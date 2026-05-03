"""WebP file format skeleton definition."""

import struct

from config.file_formats.base import FieldDef, FormatSkeleton

WEBP_SKELETON = FormatSkeleton(
    name="WebP",
    magic=b"RIFF",
    max_seed_size=65536,
    min_seed_size=32,
    fields=[
        FieldDef("riff_tag", 0, 4, fixed=True, default_value=b"RIFF"),
        FieldDef("file_size", 4, 4, fixed=False,
                 default_value=struct.pack("<I", 0x1000)),
        FieldDef("webp_tag", 8, 4, fixed=True, default_value=b"WEBP"),
        FieldDef("vp8_chunk_fourcc", 12, 4, fixed=True,
                 default_value=b"VP8 "),
        FieldDef("vp8_chunk_size", 16, 4, fixed=False,
                 default_value=struct.pack("<I", 0x0FC0)),
        FieldDef("vp8_frame_tag", 20, 3, fixed=False,
                 default_value=b"\x9D\x01\x2A",
                 description="VP8 keyframe tag"),
        FieldDef("vp8_width", 23, 2, fixed=False,
                 default_value=struct.pack("<H", 320),
                 description="Width (14 bits) + scale"),
        FieldDef("vp8_height", 25, 2, fixed=False,
                 default_value=struct.pack("<H", 240),
                 description="Height (14 bits) + scale"),
    ],
)
