"""Verified crash r4 analysis must not assert missing/unobserved samples."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "boz_new_crash_regs.py"
spec = importlib.util.spec_from_file_location("boz_new_crash_regs", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCrashRegs(unittest.TestCase):
    def test_fault_time_zero_is_definitive(self):
        raw = "\n".join([
            "[CRASH_BRIDGE] [TREE_PROBE] mode=arm32 off=002fe088 r0=00000001 r4=40b34940",
            "[CRASH_BRIDGE] [TREE_PROBE] mode=arm32 off=002fe098 r4=40b34940",
            "[CRASH_BRIDGE] signal 11 addr=0x2c pc=0x4a2fe0a8 pc_off=0x002fe0a8 "
            "sp=0x3ffff010 r0=0x3ffff014 r4=0x00000000",
        ])
        result = mod.summarize_crash_registers(raw)
        self.assertEqual(result["crash_at_2fe0a8_count"], 1)
        self.assertEqual(result["r4_null_at_crash_count"], 1)
        self.assertEqual(len(result["probe_samples"]), 2)

    def test_crash_without_r4_is_unknown(self):
        raw = "[CRASH_BRIDGE] signal 11 addr=0x2c pc_off=0x002fe0a8 r0=0x1"
        result = mod.summarize_crash_registers(raw)
        self.assertEqual(result["crash_at_2fe0a8_count"], 1)
        self.assertEqual(result["r4_null_at_crash_count"], 0)
        self.assertEqual(result["r4_at_crash_unknown_count"], 1)

    def test_missing_probe_r4_is_unknown(self):
        raw = "[CRASH_BRIDGE] [TREE_PROBE] mode=arm32 off=002fe088 r0=00000000"
        self.assertIsNone(mod.summarize_crash_registers(raw)["probe_samples"][0]["r4"])

    def test_other_fault_does_not_count(self):
        raw = "[CRASH_BRIDGE] signal 11 addr=0x2c pc_off=0x000db31e r4=0x00000000"
        out = mod.summarize_crash_registers(raw)
        self.assertEqual(out["crash_at_2fe0a8_count"], 0)
        self.assertEqual(out["r4_null_at_crash_count"], 0)

    def test_thumb_probe_is_excluded(self):
        raw = "[TREE_PROBE] mode=thumb16 off=002fe088 r4=00000000"
        self.assertEqual(mod.summarize_crash_registers(raw)["probe_samples"], [])


if __name__ == "__main__":
    unittest.main()
