"""Test selector provenance with explicit observations and missing data."""
import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools" / "boz_selector_provenance.py"
spec = importlib.util.spec_from_file_location("boz_selector_provenance", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def record(off, **values):
    return "[TREE_PROBE] off=%06x %s" % (
        off, " ".join("%s=%08x" % (key, value) for key, value in values.items())
    )


class SelectorProvenanceTests(unittest.TestCase):
    def test_full_preserved_chain(self):
        raw = "\n".join([
            record(0xDB2FA, sp28=0),
            record(0xDB2FE, sp28=0x40B34000, r0=1),
            record(0xDB306, sp28=0x40B34000),
            record(0xDB31C, sp0=0x40B34000),
            record(0xDA728, r2=0x40B34000),
            record(0xD8F0E, r2=0x40B34000),
            record(0xD8F44, r2=0x40B34000),
        ])
        out = mod.summarize(raw)
        self.assertTrue(out["chronological_chain_complete"])
        self.assertTrue(out["key_value_preserved_across_observed_chain"])
        self.assertTrue(out["registry_lookup_miss_observed"])
        self.assertEqual(out["observations"]["helper_stack_after"], "0x40b34000")

    def test_mismatched_key(self):
        raw = "\n".join([
            record(0xDB306, sp28=0x11111111),
            record(0xDB31C, sp0=0x11111111),
            record(0xDA728, r2=0x22222222),
            record(0xD8F0E, r2=0x22222222),
        ])
        out = mod.summarize(raw)
        self.assertTrue(out["chronological_chain_complete"])
        self.assertFalse(out["key_value_preserved_across_observed_chain"])

    def test_unknown_not_zero(self):
        raw = "\n".join([
            record(0xDB306, sp0=0x1234),
            record(0xDB31C, sp0=0x1234),
        ])
        out = mod.summarize(raw)
        self.assertFalse(out["chronological_chain_complete"])
        self.assertIsNone(out["observations"]["key_in_stack_local"])

    def test_wrong_order_not_a_complete_chain(self):
        raw = "\n".join([
            record(0xD8F0E, r2=0x12121212),
            record(0xDA728, r2=0x12121212),
            record(0xDB31C, sp0=0x12121212),
            record(0xDB306, sp28=0x12121212),
        ])
        self.assertFalse(mod.summarize(raw)["chronological_chain_complete"])


    def test_serializer_io_matches_destination(self):
        log = "\n".join([
            record(0xDB2FA, r0=0x3ffff0b4, sp28=0x40b34b20),
            "[S3E_FILE_RW] op=read buffer=3ffff0b4 file=40000010 "
            "elem=4 count=1 result=0 before=12 after=12 eof=1 error=0 word=00000000",
            record(0xDB2FE, sp28=0x40b34b20, r0=4),
        ])
        summary = mod.summarize(log)
        self.assertEqual(summary["helper_destination"], "0x3ffff0b4")
        self.assertEqual(len(summary["matching_io_calls"]), 1)
        self.assertEqual(summary["matching_failed_io_calls"], 1)

    def test_serializer_io_other_destination(self):
        log = "\n".join([
            record(0xDB2FA, r0=0x3ffff0b4),
            "[S3E_FILE_RW] op=read buffer=3ffff000 file=40000010 "
            "elem=4 count=1 result=0 before=12 after=12 eof=1 error=0 word=00000000",
        ])
        summary = mod.summarize(log)
        self.assertEqual(summary["matching_io_calls"], [])



if __name__ == "__main__":
    unittest.main()
