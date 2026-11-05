"""Pure models and fail-closed guards; no Unicorn or original image required."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selector_emulation as emu


class SelectorModelTests(unittest.TestCase):
    def test_flag_requires_exactly_one(self):
        for flag in (0, 2, 0xffffffff):
            self.assertEqual(emu.paired_mode(flag, 0x5002), 0x5002)
        self.assertEqual(emu.paired_mode(1, 0x5002), 0x5004)

    def test_all_reviewed_pairs(self):
        self.assertEqual(len(emu.PAIRS), 18)
        for source, target in emu.PAIRS.items():
            self.assertEqual(emu.paired_mode(1, source), target)
            self.assertEqual(emu.paired_mode(0, source), source)

    def test_other_modes_unchanged(self):
        for mode in (0, 1, 0x880, 0xb21, 0x5004, 0xa000, 0xffffffff):
            self.assertEqual(emu.paired_mode(1, mode), mode)

    def test_u32_guards(self):
        for value in (-1, 1<<32, True, 1.0, None):
            for function in (lambda: emu.paired_mode(value, 1), lambda: emu.paired_mode(1, value)):
                with self.assertRaises(ValueError):
                    function()

    def test_lookup_first_match(self):
        self.assertEqual(emu.mode_index((0x5000,0x5002,0x5002), 0x5002), 1)
        self.assertEqual(emu.mode_index((), 0x5002), 255)
        self.assertEqual(emu.mode_index((0x5000,), 0x5002), 255)

    def test_lookup_bounds(self):
        for modes in (tuple(range(256)), (True,), (-1,), (1<<32,)):
            with self.assertRaises(ValueError):
                emu.mode_index(modes, 0)

    def test_unknown_image_before_optional_emulator_import(self):
        with self.assertRaisesRegex(ValueError, 'pinned original'):
            emu.run_original(b'not a camera firmware')

    def test_image_slice_bounds(self):
        self.assertEqual(emu.image_slice(b'ab', emu.BASE, 2), b'ab')
        for address, size in ((emu.BASE-1,1), (emu.BASE,3), (emu.BASE,0)):
            with self.assertRaises(ValueError):
                emu.image_slice(b'ab', address, size)


if __name__ == '__main__':
    unittest.main()
