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



    def test_type_selector_r8_equals_r3_leads_to_primary_path(self):
        log = "\n".join([
            "[TREE_PROBE] off=0da702 r0=4065e0c8 r2=00000000 r3=40b34bd0 r8=40b34bd0",
            "[TREE_PROBE] off=0d94e4 r0=4065e0c8 r2=00000000 r4=00000000",
            "[TREE_PROBE] off=0d95be r0=00000000 r2=00000000 r4=00000000",
            "[TREE_PROBE] off=0db31e r0=00000000 r2=00000001",
        ])
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["special_type_selector_match_count"], 1)
        self.assertEqual(result["primary_factory_null_arg_count"], 1)
        self.assertEqual(result["primary_factory_null_exit_count"], 1)

    def test_type_selector_unknown_does_not_count_as_equality(self):
        log = "[TREE_PROBE] off=0da702 r8=00000000"
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["special_type_selector_match_count"], 0)



    def test_deferred_second_fallback_null_is_distinct(self):
        log = "\n".join([
            "[TREE_PROBE] off=0da71c r3=7c955bf1 r8=40b35010",
            "[TREE_PROBE] off=0da728 r0=4065d090 r8=40b35010",
            "[TREE_PROBE] off=0da72c r0=00000000 r8=40b35010",
            "[TREE_PROBE] off=0da730 r0=00000000 r8=40b35010",
            "[TREE_PROBE] off=0da702 r0=00000000 r3=00000000 r8=40b35010",
        ])
        result = module.analyze(module.parse_trace(log))
        self.assertEqual(result["second_selector_probe_count"], 1)
        self.assertEqual(result["second_selector_unequal_count"], 1)
        self.assertEqual(result["second_selector_equal_count"], 0)
        self.assertEqual(result["second_fallback_return_count"], 1)
        self.assertEqual(result["second_fallback_null_count"], 1)



    def test_second_registry_absent_handler(self):
        trace = "\n".join([
            "[TREE_PROBE] off=0d8f14 r0=4065cf70 r4=00000000 r5=00000000 r6=40aa9900",
            "[TREE_PROBE] off=0d8f36 r0=4065cf70 r4=40aa9900 r5=00000000 r6=40aa9900",
            "[TREE_PROBE] off=0d8f44 r0=4065cf70 r4=40aa9900 r6=40aa9900",
            "[TREE_PROBE] off=0d8f46 r0=00000000 r4=40aa9900 r6=40aa9900",
        ])
        result = module.analyze(module.parse_trace(trace))
        self.assertEqual(result["second_registry_root_null_count"], 1)
        self.assertEqual(result["second_registry_sentinel_selected_count"], 1)
        self.assertEqual(result["second_registry_no_handler_count"], 1)
        self.assertEqual(result["second_registry_handler_call_count"], 0)

    def test_second_registry_handler_returned_null_is_different(self):
        trace = "\n".join([
            "[TREE_PROBE] off=0d8f14 r0=4065cf70 r4=00000000 r5=40b0e400 r6=40aa9900",
            "[TREE_PROBE] off=0d8f40 r0=40b34000 r2=40b0e400 r4=40b0e400 r6=40aa9900",
            "[TREE_PROBE] off=0d8f42 r0=00000000 r4=40b0e400 r6=40aa9900",
        ])
        result = module.analyze(module.parse_trace(trace))
        self.assertEqual(result["second_registry_root_null_count"], 0)
        self.assertEqual(result["second_registry_handler_call_count"], 1)
        self.assertEqual(result["second_registry_handler_null_return_count"], 1)
        self.assertEqual(result["second_registry_no_handler_count"], 0)



if __name__ == "__main__":
    unittest.main()
