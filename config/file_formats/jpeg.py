"""JPEG file format skeleton definition."""

import struct

from config.file_formats.base import FieldDef, FormatSkeleton

JPEG_SKELETON = FormatSkeleton(
    name="JPEG",
    magic=b"\xFF\xD8\xFF",
    max_seed_size=65536,
    min_seed_size=32,
    fields=[
        FieldDef("soi", 0, 2, fixed=True, default_value=b"\xFF\xD8",
                 description="Start of Image marker"),
        FieldDef("app0_marker", 2, 2, fixed=True, default_value=b"\xFF\xE0",
                 description="APP0 marker"),
        FieldDef("app0_length", 4, 2, fixed=False,
                 default_value=struct.pack(">H", 16)),
        FieldDef("jfif_identifier", 6, 5, fixed=True,
                 default_value=b"JFIF\x00"),
        FieldDef("jfif_version", 11, 2, fixed=False,
                 default_value=b"\x01\x02"),
        FieldDef("sof_marker", 13, 2, fixed=True, default_value=b"\xFF\xC0",
                 description="Start of Frame (baseline)"),
        FieldDef("sof_length", 15, 2, fixed=False,
                 default_value=struct.pack(">H", 17)),
        FieldDef("sos_marker", 17, 2, fixed=True, default_value=b"\xFF\xDA",
                 description="Start of Scan marker"),
        FieldDef("eoi", 19, 2, fixed=True, default_value=b"\xFF\xD9",
                 description="End of Image marker"),
    ],
)
