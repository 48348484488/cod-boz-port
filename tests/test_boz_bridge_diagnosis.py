"""Regression tests for BOZ pre/post MOV register observations."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "boz_bridge_diagnosis.py"
spec = importlib.util.spec_from_file_location("boz_bridge_diagnosis", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestCrashBridge(unittest.TestCase):
    def test_real_trace_pre_move_is_not_return(self):
        # Observed 2026-10-05. DA79A executes mov r0,r4 AFTER sampling.
        log = "\n".join([
            "[TREE_PROBE] mode=thumb16 off=0da70e r0=00000000 r4=00000000",
            "[TREE_PROBE] mode=thumb16 off=0da72c r0=40b34a28 r4=4a45ef00",
            "[TREE_PROBE] mode=thumb16 off=0da79a r0=00000000 r4=40b34a28",
            "[TREE_PROBE] mode=thumb16 off=0db31e r0=00000000 r4=4065df78",
        ])
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["owner_pre_mov_r0_zero_count"], 1)
        self.assertEqual(result["owner_pre_mov_r4_nonzero_count"], 1)
        self.assertEqual(result["owner_after_mov_samples"], 0)
        self.assertEqual(result["crash_site_zero_r0_count"], 1)
        self.assertEqual(result["fallback_nonzero_r0_count"], 1)

    def test_after_mov_confirms_register_copy(self):
        log = "\n".join([
            "[TREE_PROBE] off=0da79a r0=00000000 r4=40B34A28",
            "[TREE_PROBE] off=0da79c r0=40B34A28 r4=40B34A28",
        ])
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["post_mov_nonzero_r0_count"], 1)
        self.assertEqual(result["post_mov_matches"], 1)
        self.assertTrue(result["post_mov_checks"][0]["matches"])

    def test_missing_registers_do_not_masquerade_as_zero(self):
        log = "[TREE_PROBE] off=0da79a r4=40b34a28\n[TREE_PROBE] off=0da79c r4=40b34a28"
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["owner_pre_mov_r0_zero_count"], 0)
        self.assertEqual(result["post_mov_zero_r0_count"], 0)
        self.assertEqual(result["post_mov_matches"], 0)

    def test_order_must_be_pre_then_post(self):
        log = "\n".join([
            "[TREE_PROBE] off=0da79c r0=40b34a28 r4=40b34a28",
            "[TREE_PROBE] off=0da79a r0=00000000 r4=40b34a28",
        ])
        self.assertEqual(module.analyze(module.parse_trace(log))["post_mov_matches"], 0)

    def test_different_value_detected(self):
        log = "\n".join([
            "[TREE_PROBE] off=0da79a r0=00000000 r4=40b34a28",
            "[TREE_PROBE] off=0da79c r0=00000000 r4=40b34a28",
        ])
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["post_mov_matches"], 0)
        self.assertEqual(result["post_mov_zero_r0_count"], 1)

    def test_leading_zero_offset_and_hex_case(self):
        events = module.parse_trace("[TREE_PROBE] mode=thumb16 off=000da79A r0=00000000 r4=40B34A28")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["label"], "owner_before_mov_r0_r4")

    def test_json_event_format_and_ignore_diagnostic(self):
        result = module.analyze([
            {"type": "diagnostic", "off": "0xda79a", "r0": "0x00000000"},
            {"type": "probe", "off": "0xda79a", "r0": "0x00000000", "r4": "0x40b34a28"},
            {"type": "probe", "off": "0xda79c", "r0": "0x40b34a28", "r4": "0x40b34a28"},
        ])
        self.assertEqual(result["probe_count"], 2)
        self.assertEqual(result["post_mov_matches"], 1)


    def test_verify_instruction_boundaries(self):
        rows = [
            (0xDA79A, "da79a: 4620  mov r0, r4"),
            (0xDA79C, "da79c: b005  add sp, #20"),
            (0xDA79E, "da79e: e8bd 8ff0  ldmia sp!, {..., pc}"),
        ]
        self.assertTrue(module.is_owner_after_mov_safe(rows))
        self.assertFalse(module.is_owner_after_mov_safe([
            (0xDA79A, "da79a: 4620  mov r0, r4"), (0xDA79E, "wrong boundary")
        ]))
        self.assertFalse(module.is_owner_after_mov_safe([
            (0xDA79A, "da79a: 4620  mov r1, r4"), (0xDA79C, "next")
        ]))



    def test_primary_factory_null_arg_proof(self):
        rows = [
            (0xD94EE, "d94ee: 4614 mov r4, r2"),
            (0xD94F2, "d94f2: 2a00 cmp r2, #0"),
            (0xD94F4, "d94f4: d062 beq.n 0xd95bc"),
            (0xD95BC, "d95bc: 4620 mov r0, r4"),
            (0xD95BE, "d95be: e8bd 81f0 ldmia.w sp!, {r4, r5, r6, r7, r8, pc}"),
        ]
        proof = module.verify_primary_factory_null_path(rows)
        self.assertTrue(proof["r2_zero_short_circuit_verified"])
        self.assertIn("return nullptr", proof["cxx_equivalent_for_this_path_only"])

        # A missing or changed branch must not produce an automatic proof.
        bad = [(off, line.replace("beq.n", "bne.n")) for off, line in rows]
        self.assertFalse(
            module.verify_primary_factory_null_path(bad)["r2_zero_short_circuit_verified"]
        )



if __name__ == "__main__":
    unittest.main()
