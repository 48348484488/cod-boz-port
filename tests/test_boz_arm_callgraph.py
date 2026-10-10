"""Regression tests for offline ARM callsite scanning."""
import importlib.util
import struct
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "tools" / "boz_arm_callgraph.py"
spec = importlib.util.spec_from_file_location("boz_arm_callgraph", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def synthetic_image(code: bytes) -> bytes:
    header = bytearray(68)
    header[:4] = b"XE3U"
    struct.pack_into("<III", header, 20, 68, len(code), len(code))
    return bytes(header) + code


def encode_arm_bl(site: int, target: int) -> bytes:
    diff = target - (site + 8)
    assert diff % 4 == 0
    return struct.pack("<I", 0xeb000000 | ((diff // 4) & 0xffffff))


class TestARMCallgraph(unittest.TestCase):
    def test_finds_direct_arm_bl_callers(self):
        code = bytearray(32)
        code[0:4] = encode_arm_bl(0, 20)
        code[4:8] = encode_arm_bl(4, 20)
        self.assertEqual(mod.arm_bl_candidates(synthetic_image(code), 20), [0, 4])

    def test_does_not_confuse_arm_branch_without_link(self):
        code = bytearray(32)
        code[0:4] = struct.pack("<I", 0xea000003)  # B target=20
        code[4:8] = encode_arm_bl(4, 20)
        self.assertEqual(mod.arm_bl_candidates(synthetic_image(code), 20), [4])

    def test_image_validation(self):
        with self.assertRaises(ValueError):
            mod.arm_bl_candidates(b"invalid", 0)
        with self.assertRaises(ValueError):
            mod.arm_bl_candidates(synthetic_image(bytes(32)), 3)
        with self.assertRaises(ValueError):
            mod.arm_bl_candidates(synthetic_image(bytes(32)), 32)

    def test_backward_bl(self):
        code = bytearray(32)
        code[28:32] = encode_arm_bl(28, 4)
        self.assertEqual(mod.arm_bl_candidates(synthetic_image(code), 4), [28])


if __name__ == "__main__":
    unittest.main()
