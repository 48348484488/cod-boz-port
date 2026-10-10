"""Minimal synthetic S3E fixup records for deterministic PLT symbol tests."""
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "boz_s3e_imports.py"
spec = importlib.util.spec_from_file_location("boz_s3e_imports", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_image():
    names = b"s3eFileRead\0"
    table = struct.pack("<IIH", 0, 10+len(names), 1)+names
    slot = 0x54
    external = struct.pack("<IIIHHH",2,18,1,0,slot,0)
    fixups=table+external
    image = bytearray(0x200+0x100)
    image[:4]=b"XE3U"
    struct.pack_into("<IIII",image,12,68,len(fixups),0x200,0x100)
    image[68:68+len(fixups)]=fixups
    struct.pack_into("<III",image,0x200+0x20,
        0xe28fc000,0xe28cc000,0xe5bcf02c)
    return bytes(image)


class TestS3EImportResolver(unittest.TestCase):
    def test_actual_fixup_record_shape(self):
        info=mod.resolve_plt(test_image(),0x20)
        self.assertEqual(info["symbol"],"s3eFileRead")
        self.assertEqual(info["got_slot"],"0x54")

    def test_invalid_stub_rejected(self):
        with self.assertRaisesRegex(ValueError,"PLT"):
            mod.resolve_plt(test_image(),0x30)

    def test_invalid_import_offset_rejected(self):
        with self.assertRaisesRegex(ValueError,"PLT"):
            mod.resolve_plt(test_image(),0x102)

    def test_modified_symbol_mapping_not_guessed(self):
        data=bytearray(test_image())
        data[68+10:68+10+11] = b"s3eFileWrit"
        self.assertTrue(mod.resolve_plt(bytes(data),0x20)["symbol"].startswith("s3eFileWrit"))


if __name__ == "__main__":
    unittest.main()
