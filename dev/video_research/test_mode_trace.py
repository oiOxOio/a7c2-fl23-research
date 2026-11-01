"""Synthetic tests of bounded static scanning; no Capstone or firmware needed."""
from pathlib import Path
import importlib.util
import struct
import unittest

spec = importlib.util.spec_from_file_location('mode_trace_tested', Path(__file__).with_name('mode_trace.py'))
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def instruction(value, register=3, top=False):
    first = (0xf2c0 if top else 0xf240) | (value >> 12) | (((value >> 11) & 1) << 10)
    second = (((value >> 8) & 7) << 12) | (register << 8) | (value & 255)
    return struct.pack('<HH', first, second)


class ModeTraceTests(unittest.TestCase):
    def test_movw_5002(self):
        self.assertEqual(trace.decode_mov_halfwords(*struct.unpack('<HH', instruction(0x5002))), ('movw', 3, 0x5002))

    def test_all_immediate_bits(self):
        for value in (0, 255, 0x5002, 0x99d4, 0xffff, 0x0800, 0x0700):
            for top in (False, True):
                self.assertEqual(trace.decode_mov_halfwords(*struct.unpack('<HH', instruction(value, 12, top))),
                                 ('movt' if top else 'movw', 12, value))

    def test_reject_noninstruction(self):
        for pair in ((0, 0), (0xf245, 0x8002), (0xf245, 0x0f02), (-1, 0), (0xffff, 0xffff)):
            self.assertIsNone(trace.decode_mov_halfwords(*pair))

    def test_truncated_and_odd_trailer(self):
        self.assertEqual(trace.immediate_candidates(b'\x45\xf2\x02', {0x5002})['total'], 0)
        self.assertEqual(trace.immediate_candidates(instruction(0x5002)+b'x', {0x5002})['total'], 1)

    def test_candidates_are_not_proof(self):
        result = trace.immediate_candidates(instruction(0x5002)*3, {0x5002}, maximum=2)
        self.assertEqual(result['total'], 3)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['candidates']), 2)
        self.assertFalse(result['candidates'][0]['instruction_boundary_verified'])

    def test_movt_not_reported_as_mode(self):
        self.assertEqual(trace.immediate_candidates(instruction(0x5002, top=True), {0x5002})['total'], 0)

    def test_bounds(self):
        self.assertEqual(trace.file_offset(trace.BASE+4, 4, 8), 4)
        for va, size in ((trace.BASE-1, 1), (trace.BASE+5, 4), (trace.BASE, 0)):
            with self.assertRaises(ValueError):
                trace.file_offset(va, size, 8)

    def test_unknown_image_rejected_before_decoder_import(self):
        with self.assertRaises(ValueError):
            trace.inspect(b'not firmware')

    def test_network_requires_explicit_acceptance(self):
        with self.assertRaises(SystemExit):
            trace.main([])


class PointerTableTests(unittest.TestCase):
    def table(self, size=128, root=8):
        data = bytearray(size)
        slots = {4: 0x1235, 12: 0x5679, 20: 0xabcd}
        for offset, value in slots.items():
            struct.pack_into('<I', data, root+offset, value)
        return bytes(data), slots

    def test_exact_slots(self):
        data, slots = self.table()
        report = trace.pointer_table_candidates(data, slots)
        self.assertEqual(report['total'], 1)
        self.assertEqual(report['candidates'][0]['file_offset'], '0x8')
        self.assertFalse(report['candidates'][0]['runtime_receiver_verified'])

    def test_different_third_slot(self):
        data, slots = self.table()
        slots[20] ^= 2
        self.assertEqual(trace.pointer_table_candidates(data, slots)['total'], 0)

    def test_unaligned_table_rejected(self):
        data, slots = self.table(root=7)
        self.assertEqual(trace.pointer_table_candidates(data, slots)['total'], 0)

    def test_below_file_and_truncation(self):
        slots = {4: 0x1235, 12: 0x5679}
        self.assertEqual(trace.pointer_table_candidates(struct.pack('<I', 0x1235), slots)['total'], 0)
        data, slots = self.table()
        self.assertEqual(trace.pointer_table_candidates(data[:24], slots)['total'], 0)

    def test_bounded_matches(self):
        data, slots = self.table(size=32)
        report = trace.pointer_table_candidates(data*4, slots, maximum=2)
        self.assertEqual(report['total'], 4)
        self.assertEqual(len(report['candidates']), 2)
        self.assertTrue(report['truncated'])

    def test_invalid_pattern(self):
        for slots in ({}, {-4: 1}, {1: 1}, {4: -1}, {4: 2**32}):
            with self.assertRaises(ValueError):
                trace.pointer_table_candidates(bytes(32), slots)

    def test_thumb_state_bit_is_not_stripped(self):
        data, slots = self.table()
        slots[4] &= ~1
        self.assertEqual(trace.pointer_table_candidates(data, slots)['total'], 0)


if __name__ == '__main__':
    unittest.main()
