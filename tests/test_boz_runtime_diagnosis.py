"""Tests that an empty tree during lookup does not prove a missing insert."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "remote_build.py"
spec = importlib.util.spec_from_file_location("boz_remote_build_test", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestRuntimeEvidence(unittest.TestCase):
    def test_empty_registry_at_lookup_is_observation_only(self):
        trace = "\n".join([
            "[D8FF0_ENTER] manager=4065df78 key=4a399300 key_bytes=keyRepeatDelay",
            "[D8FF0_HASH] hash=ac54941e manager=4065df78 sentinel=40acd1b8 root=00000000",
            "[DA6C6_ENTER] r0=00000000 lr=4a0d8ffb",
            "[NULL_OBJECT] BOZ+0x0db31e after BLX r12",
        ])
        diagnosis = module.analyze_boz_output(trace)
        self.assertTrue(diagnosis["empty_registry_tree"])
        self.assertEqual(diagnosis["observed_condition"], "registry_root_null_at_lookup")
        self.assertIsNone(diagnosis["root_cause_candidate"])
        self.assertEqual(diagnosis["confidence"], "insufficient")
        self.assertNotIn("failed_stage", diagnosis)

    def test_no_lookup_cannot_claim_empty_root(self):
        result = module.analyze_boz_output("[NULL_OBJECT] BOZ+0x0db31e after BLX r12")
        self.assertNotIn("empty_registry_tree", result)
        self.assertEqual(result["confidence"], "high")


if __name__ == "__main__":
    unittest.main()
