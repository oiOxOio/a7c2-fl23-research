"""Synthetic decoder tests; none of these cases claim real-camera coverage."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selector_trace as trace


def encode(at, target, *, link=True):
    displacement = target-at-4
    if displacement % 2 or not -(1<<24) <= displacement < (1<<24):
        raise ValueError('Test branch out of range')
    value = displacement & ((1<<25)-1)
    sign, i1, i2 = (value>>24)&1, (value>>23)&1, (value>>22)&1
    first = 0xf000 | sign<<10 | ((value>>12)&0x3ff)
    second = (0xd000 if link else 0x9000) | (1^i1^sign)<<13 | (1^i2^sign)<<11 | ((value>>1)&0x7ff)
    return first, second


class BranchTests(unittest.TestCase):
    def test_known_bl_zero(self):
        self.assertEqual(trace.decode_direct_branch(0xf000, 0xf800, 0x1000), ('bl', 0x1004))

    def test_known_backward_bl(self):
        self.assertEqual(trace.decode_direct_branch(0xf7ff, 0xfffe, 0x1000), ('bl', 0x1000))

    def test_known_bw_zero(self):
        self.assertEqual(trace.decode_direct_branch(0xf000, 0xb800, 0x1000), ('b.w', 0x1004))

    def test_signed_range_and_bits(self):
        at = 0x2000000
        for delta in (-0x1000000, -0xfffffe, -0x800000, -4096, -2, 0, 2, 4096, 0x7ffffe, 0xfffffe):
            for link in (False, True):
                with self.subTest(delta=delta, link=link):
                    target = at+4+delta
                    self.assertEqual(trace.decode_direct_branch(*encode(at, target, link=link), at),
                                     ('bl' if link else 'b.w', target))

    def test_blx_conditional_and_nonbranch_excluded(self):
        for first, second in ((0xf000, 0xe800), (0xf000, 0x8000), (0xbf00, 0xf800), (0xf240, 0x0000)):
            self.assertIsNone(trace.decode_direct_branch(first, second, 0x1000))

    def test_invalid_input(self):
        for args in ((-1, 0, 0), (0, 65536, 0), (0, 0, 3), (True, 0, 0), (0, 0, 0xffffffff)):
            with self.assertRaises(ValueError):
                trace.decode_direct_branch(*args)

    def test_scanning_and_truncation(self):
        data = b''.join(struct.pack('<HH', *encode(0x1000+i*4, 0x2000)) for i in range(3))
        report = trace.direct_call_candidates(data, {0x2000}, base=0x1000, maximum=2)['0x2000']
        self.assertEqual(report['total'], 3)
        self.assertTrue(report['truncated'])
        self.assertEqual(len(report['candidates']), 2)
        self.assertFalse(report['candidates'][0]['instruction_boundary_verified'])
        self.assertFalse(report['candidates'][0]['reachable_from_movie'])

    def test_truncated_mapping(self):
        for data in (b'', b'\0', b'\0'*3):
            report = trace.direct_call_candidates(data, {0x2000}, base=0x1000)
            self.assertEqual(report['0x2000']['total'], 0)

    def test_invalid_scan_bounds(self):
        for kwargs in ({'maximum':0}, {'maximum':1025}, {'base':1}, {'base':-2}, {'maximum':True}):
            with self.assertRaises(ValueError):
                trace.direct_call_candidates(b'', {0x2000}, **kwargs)
        for targets in (set(), {3}, {-2}, {True}):
            with self.assertRaises(ValueError):
                trace.direct_call_candidates(b'', targets)

    def test_bounded_ascii(self):
        data = b'\xffName\0\x01bad\0unterminated'
        self.assertEqual(trace.bounded_ascii(data, 0x1001, base=0x1000), 'Name')
        for at in (0xfff, 0x1000, 0x1006, 0x100b, 0x3000):
            self.assertIsNone(trace.bounded_ascii(data, at, base=0x1000))

    def test_explicit_network_consent(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            trace.main([])


if __name__ == '__main__':
    unittest.main()
