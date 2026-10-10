"""Offline S3E code-offset mapping checks; no proprietary binary needed."""
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "boz_s3e_disasm.py"
spec = importlib.util.spec_from_file_location("boz_s3e_disasm", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fake_s3e(code: bytes):
    header = bytearray(80)
    header[:4] = b"XE3U"
    struct.pack_into("<III", header, 20, 80, len(code), len(code))
    return bytes(header) + code


class TestS3EDisasmMapping(unittest.TestCase):
    def test_extract_exact_code_bytes(self):
        blob = fake_s3e(bytes(range(64)))
        section, meta = mod.read_window(blob, 12, 20)
        self.assertEqual(section, bytes(range(12, 20)))
        self.assertEqual(meta["file_offset"], 92)

    def test_reject_missing_header(self):
        with self.assertRaisesRegex(ValueError, "XE3U"):
            mod.read_window(b"\x00" * 300, 0, 10)

    def test_reject_out_of_bounds(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            mod.read_window(fake_s3e(b"1234"), 0, 8)

    def test_reject_wrong_mode_or_unaligned(self):
        blob = fake_s3e(bytes(range(16)))
        with self.assertRaisesRegex(ValueError, "Mode"):
            mod.disassemble(blob, 0, 4, "mips")
        with self.assertRaisesRegex(ValueError, "boundary"):
            mod.disassemble(blob, 2, 8, "arm")


if __name__ == "__main__":
    unittest.main()
