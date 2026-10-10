"""Unit tests for BOZ BLX + return correlation, with no execution mockups."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "boz_handler_pairs.py"
spec = importlib.util.spec_from_file_location("boz_handler_pairs", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestHandlerPairs(unittest.TestCase):
    def test_identical_seq_and_target_required(self):
        log = "\n".join([
            "[HANDLER_PAIR_CALL] seq=1 target=4a0d8ce5 r0=4a3a320e r1=00000000 r2=4a0d8ce5 armed_return=1",
            "[HANDLER_PAIR_RET] seq=1 target=4a0d8ce5 result=00000000",
        ])
        output = module.summarize_handler_pairs(log)
        self.assertEqual(output["verified_pair_count"], 1)
        self.assertEqual(output["returned_null_count"], 1)
        self.assertEqual(output["pairs"][0]["target"], "0x4a0d8ce5")

    def test_rearmed_returns_are_counted_separately(self):
        log = "\n".join([
            "[HANDLER_PAIR_CALL] seq=1 target=4a0d8ce5 r0=4a3a320e r1=00000000 r2=4a0d8ce5 armed_return=1",
            "[HANDLER_PAIR_RET] seq=1 target=4a0d8ce5 result=40b34b10",
            "[HANDLER_PAIR_CALL] seq=2 target=4a0d8ce5 r0=4a3a320f r1=00000000 r2=4a0d8ce5 armed_return=1",
            "[HANDLER_PAIR_RET] seq=2 target=4a0d8ce5 result=00000000",
        ])
        output = module.summarize_handler_pairs(log)
        self.assertEqual(output["verified_pair_count"], 2)
        self.assertEqual(output["returned_nonnull_count"], 1)
        self.assertEqual(output["returned_null_count"], 1)

    def test_no_claim_on_missing_or_mismatched_return(self):
        log = "\n".join([
            "[HANDLER_PAIR_CALL] seq=1 target=4a0d8ce5 r0=4a3a320e r1=00000000 r2=4a0d8ce5 armed_return=1",
            "[HANDLER_PAIR_RET] seq=2 target=4a0d8ce5 result=00000000",
            "[HANDLER_PAIR_RET] seq=1 target=4a0d8ce6 result=00000000",
        ])
        output = module.summarize_handler_pairs(log)
        self.assertEqual(output["verified_pair_count"], 0)
        self.assertEqual(output["incomplete_call_count"], 1)
        self.assertEqual(output["orphan_return_count"], 2)

    def test_failed_arm_does_not_prove_return(self):
        log = "[HANDLER_PAIR_CALL] seq=1 target=4a0d8ce5 r0=00000000 r1=00000000 r2=4a0d8ce5 armed_return=0"
        output = module.summarize_handler_pairs(log)
        self.assertEqual(output["verified_pair_count"], 0)
        self.assertEqual(output["ignored_unarmed_or_duplicate_calls"], 1)


if __name__ == "__main__":
    unittest.main()
