"""Pure synthetic model checks; original instruction execution is separate."""
import sys
import unittest
from unittest.mock import patch

import request_emulation as r

MODES = (0x5000, 0x5001, 0x5002, 0x5004, 0x5020, 0x5021)


class AvailabilityTests(unittest.TestCase):
    def test_present_and_excluded(self):
        self.assertEqual(r.available(MODES, 0x5002, 0), 1)
        self.assertEqual(r.available(MODES, 0x5002, 0x5002), 0)

    def test_missing_and_empty(self):
        self.assertEqual(r.available(MODES, 0xFFFF, 0), 0)
        self.assertEqual(r.available((), 0x5002, 0), 0)

    def test_exclusion_is_unsigned_halfword(self):
        for value in (-1, 65536, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.available(MODES, 0x5002, value)

    def test_mode_bounds(self):
        for value in (-1, 1 << 32, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.available(MODES, value, 0)
        with self.assertRaises(ValueError):
            r.available(tuple(range(256)), 1, 0)

    def test_flag_zero_prefers_5002(self):
        self.assertEqual(r.select_mode(MODES, 0, 0, 0), 0x5002)

    def test_exclusion_selects_fallback(self):
        self.assertEqual(r.select_mode(MODES, 0, 0, 0x5002), 0x5020)
        self.assertEqual(r.select_mode(MODES, 1, 0, 0x5004), 0x5021)

    def test_pairing_requires_exactly_one(self):
        self.assertEqual(r.select_mode(MODES, 1, 0, 0), 0x5004)
        self.assertEqual(r.select_mode(MODES, 2, 0, 0), 0x5002)
        self.assertEqual(r.select_mode(MODES, 0xFFFFFFFF, 0, 0), 0x5002)

    def test_probe_nonzero_is_not_converter_equal_one(self):
        self.assertEqual(r.select_mode(MODES, 2, 0, 0x5004), 0x5020)
        self.assertEqual(r.select_mode(MODES, 2, 0, 0x5002), 0x5002)

    def test_empty_list_fallback_not_evidence_of_support(self):
        self.assertEqual(r.select_mode((), 0, 0, 0), 0x5000)
        self.assertEqual(r.select_mode((), 1, 0, 0), 0x5001)

    def test_policy_1_is_not_stubbed(self):
        with self.assertRaises(ValueError):
            r.select_mode(MODES, 0, 1, 0)
        self.assertEqual(r.select_mode(MODES, 0, 2, 0), 0x5002)

    def test_invalid_flags(self):
        for flag, policy in [(True, 0), (-1, 0), (0, -1), (0, True)]:
            with self.subTest(flag=flag, policy=policy), self.assertRaises(ValueError):
                r.select_mode(MODES, flag, policy, 0)

    def test_entire_instruction_inside_single_range(self):
        bounds = ((10, 14), (14, 18))
        self.assertTrue(r.contains(bounds, 10, 4))
        self.assertFalse(r.contains(bounds, 12, 4))
        self.assertFalse(r.contains(bounds, 10, 0))
        self.assertFalse(r.contains(bounds, True, 1))

    def test_identity_before_optional_emulator(self):
        with patch.dict(sys.modules, {'unicorn': None}):
            with self.assertRaisesRegex(ValueError, 'Unrecognized original'):
                r.run_original(b'not original firmware')


if __name__ == '__main__':
    unittest.main()
