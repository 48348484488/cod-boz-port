"""Regression tests for the BOZ ARM/Thumb NULL owner trace."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'boz_bridge_diagnosis.py'
spec = importlib.util.spec_from_file_location('boz_bridge_diagnosis', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestCrashBridge(unittest.TestCase):
    def test_actual_observed_register_transition(self):
        # Registers observed on Render 2026-10-05. Other fields are irrelevant.
        trace = '\n'.join([
            '[CRASH_BRIDGE] [TREE_PROBE] mode=thumb16 off=0da70e r0=00000000 r4=00000000',
            '[CRASH_BRIDGE] [TREE_PROBE] mode=thumb16 off=0da72c r0=40b34a28 r4=4a45ef00',
            '[CRASH_BRIDGE] [TREE_PROBE] mode=thumb16 off=0da79a r0=00000000 r4=40b34a28',
            '[CRASH_BRIDGE] [TREE_PROBE] mode=thumb16 off=0db31e r0=00000000 r4=4065df78',
        ])
        result = module.analyze(module.parse_trace(trace))
        self.assertEqual(result['owner_r0_zero_count'], 1)
        self.assertEqual(result['r4_based_detection_missed'], 1)
        self.assertEqual(result['observed_null_dispatch_chains'], 1)
        self.assertEqual(result['chains'][0]['fallback']['r0'], 0x40b34a28)

    def test_no_fake_zero_when_register_missing(self):
        trace = '[TREE_PROBE] off=0da79a r4=40b34a28\n[TREE_PROBE] off=0db31e r4=4065df78'
        result = module.analyze(module.parse_trace(trace))
        self.assertEqual(result['owner_r0_zero_count'], 0)
        self.assertEqual(result['observed_null_dispatch_chains'], 0)

    def test_non_null_owner_result_no_crash_chain(self):
        trace = '\n'.join([
            '[TREE_PROBE] off=0da72c r0=40b34a28',
            '[TREE_PROBE] off=0da79a r0=40b34a28 r4=40b34a28',
            '[TREE_PROBE] off=0db31e r0=40b34a28',
        ])
        self.assertEqual(module.analyze(module.parse_trace(trace))['observed_null_dispatch_chains'], 0)

    def test_reverse_order_is_not_a_chain(self):
        trace = '\n'.join([
            '[TREE_PROBE] off=0db31e r0=00000000',
            '[TREE_PROBE] off=0da79a r0=00000000 r4=40b34a28',
            '[TREE_PROBE] off=0da72c r0=40b34a28',
        ])
        self.assertEqual(module.analyze(module.parse_trace(trace))['observed_null_dispatch_chains'], 0)

    def test_leading_zero_offset_and_hex_case(self):
        trace = '[TREE_PROBE] mode=thumb16 off=000da79A r0=00000000 r4=40B34A28'
        events = module.parse_trace(trace)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['label'], 'owner_return')


if __name__ == '__main__':
    unittest.main()
