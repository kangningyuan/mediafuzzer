"""GIF file format skeleton definition."""

import struct

from config.file_formats.base import FieldDef, FormatSkeleton

GIF_SKELETON = FormatSkeleton(
    name="GIF",
    magic=b"GIF89a",
    max_seed_size=65536,
    min_seed_size=32,
    fields=[
        FieldDef("signature", 0, 6, fixed=True, default_value=b"GIF89a",
                 description="GIF signature"),
        FieldDef("logical_screen_width", 6, 2, fixed=False,
                 default_value=struct.pack("<H", 320)),
        FieldDef("logical_screen_height", 8, 2, fixed=False,
                 default_value=struct.pack("<H", 240)),
        FieldDef("gct_packed", 10, 1, fixed=False,
                 default_value=b"\xF7",
                 description="GCT flag + color resolution + sort + GCT size"),
        FieldDef("bg_color_index", 11, 1, fixed=False,
                 default_value=b"\x00"),
        FieldDef("pixel_aspect_ratio", 12, 1, fixed=False,
                 default_value=b"\x00"),
        FieldDef("image_descriptor", 13, 10, fixed=False,
                 default_value=b"\x2C" + b"\x00" * 9,
                 description="Image separator + left/top/width/height + packed"),
        FieldDef("lzw_min_code_size", 23, 1, fixed=False,
                 default_value=b"\x08"),
        FieldDef("image_data_block", 24, 4, fixed=False,
                 default_value=b"\x02\x4C\x01\x00",
                 description="Sub-block: size + LZW data + block terminator"),
        FieldDef("trailer", 28, 1, fixed=True,
                 default_value=b"\x3B",
                 description="GIF trailer marker"),
    ],
)
