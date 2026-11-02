"""Artificial bytes only; no network, USB or Sony firmware fixture."""
import struct
import sys
import unittest
from unittest.mock import patch

import request_trace as r


def elf_fixture():
    data = bytearray(768)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0, 64, 128, 0, 64, 56, 1, 64, 3, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x1000, 0, 768, 800, 0x1000)
    struct.pack_into('<IIQQQQIIQQ', data, 192, 0, 3, 0, 0, 400, 15, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 256, 0, 11, 0, 0, 480, 48, 1, 0, 8, 24)
    data[400:415] = b'\0MovieFormat\0xx'
    struct.pack_into('<IBBHQQ', data, 504, 1, 0x12, 0, 1, 0x1200, 16)
    return data


class SpanTests(unittest.TestCase):
    def test_exact_end_and_empty(self):
        self.assertEqual(r.span(b'abcd', 1, 3), b'bcd')
        self.assertEqual(r.span(b'abcd', 4, 0), b'')

    def test_bad_spans(self):
        for off, size in [(-1, 1), (0, -1), (3, 2), (5, 0), (True, 1), (0, 1.0)]:
            with self.subTest(off=off, size=size), self.assertRaises(ValueError):
                r.span(b'abcd', off, size)

    def test_mapping_bounds(self):
        self.assertEqual(r.cp_span(b'ab', 0x102, 0, base=0x100), b'')
        with self.assertRaises(ValueError):
            r.cp_span(b'ab', 0xFF, 1, base=0x100)


class TableTests(unittest.TestCase):
    def test_tbh(self):
        raw = bytes.fromhex('dfe812f0') + struct.pack('<HH', 2, 4) + bytes(8)
        table = r.pc_table(raw, 0, 2, base=0)
        self.assertEqual(table['kind'], 'tbh')
        self.assertEqual(table['index_register'], 'r2')
        self.assertEqual([e['target'] for e in table['entries']], ['0x8', '0xc'])
        self.assertFalse(table['targets_are_instruction_boundaries'])

    def test_tbb_at_halfword_boundary_does_not_word_align_pc(self):
        raw = bytes(2) + bytes.fromhex('dfe800f0') + bytes([1, 3]) + bytes(8)
        table = r.pc_table(raw, 2, 2, base=0)
        self.assertEqual(table['table'], '0x6')
        self.assertEqual([e['target'] for e in table['entries']], ['0x8', '0xc'])

    def test_non_pc_table_rejected(self):
        with self.assertRaises(ValueError):
            r.pc_table(bytes.fromhex('d1e812f0') + bytes(20), 0, 1, base=0)

    def test_bad_count_and_alignment(self):
        for a, c in [(1, 1), (0, 0), (0, 257), (0, True)]:
            with self.subTest(a=a, c=c), self.assertRaises(ValueError):
                r.pc_table(bytes(24), a, c, base=0)

    def test_truncated_table(self):
        with self.assertRaises(ValueError):
            r.pc_table(bytes.fromhex('dfe812f0'), 0, 2, base=0)

    def test_overlap_and_external_target(self):
        for v in (0, 0xFFFF):
            raw = bytes.fromhex('dfe812f0') + struct.pack('<H', v) + bytes(8)
            with self.subTest(v=v), self.assertRaises(ValueError):
                r.pc_table(raw, 0, 1, base=0)

    def test_bad_index_register(self):
        for value in (0xF00D, 0xF01F):
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.pc_table(struct.pack('<HH', 0xE8DF, value)+bytes(8), 0, 1, base=0)


class ElfTests(unittest.TestCase):
    def test_symbol_and_segment_mapping(self):
        elf = r.Elf64(elf_fixture())
        sym = list(elf.symbols())[0]
        self.assertEqual(sym['name'], 'MovieFormat')
        self.assertEqual(sym['type'], 2)
        self.assertEqual(elf.file_offset(sym['va'], sym['size']), 512)

    def test_bss_is_not_file_backed(self):
        with self.assertRaises(ValueError):
            r.Elf64(elf_fixture()).file_offset(0x1300, 1)

    def test_invalid_elf_identity(self):
        for position, value in [(0, 0), (4, 1), (5, 2), (18, 40)]:
            data = elf_fixture()
            data[position] = value
            with self.subTest(position=position), self.assertRaises(ValueError):
                r.Elf64(data)

    def test_truncated_header(self):
        with self.assertRaises(ValueError):
            r.Elf64(bytes(8))

    def test_invalid_section_extent(self):
        data = elf_fixture()
        struct.pack_into('<Q', data, 192+32, 1000)
        with self.assertRaises(ValueError):
            r.Elf64(data)

    def test_invalid_string_link(self):
        data = elf_fixture()
        struct.pack_into('<I', data, 256+40, 9)
        with self.assertRaises(ValueError):
            list(r.Elf64(data).symbols())

    def test_invalid_symbol_name(self):
        data = elf_fixture()
        struct.pack_into('<I', data, 504, 99)
        with self.assertRaises(ValueError):
            list(r.Elf64(data).symbols())

    def test_missing_terminator(self):
        data = elf_fixture()
        data[400:415] = b'x'*15
        with self.assertRaises(ValueError):
            list(r.Elf64(data).symbols())

    def test_symbol_entry_size(self):
        data = elf_fixture()
        struct.pack_into('<Q', data, 256+56, 16)
        with self.assertRaises(ValueError):
            list(r.Elf64(data).symbols())

    def test_ambiguous_mapping(self):
        elf = r.Elf64(elf_fixture())
        elf.loads.append(elf.loads[0])
        with self.assertRaises(ValueError):
            elf.file_offset(0x1200, 1)


class StringAndInverseMapTests(unittest.TestCase):
    def test_inverse_segment_map(self):
        self.assertEqual(r.Elf64(elf_fixture()).virtual_address(512,16), 0x1200)
        with self.assertRaises(ValueError):
            r.Elf64(elf_fixture()).virtual_address(768,1)

    def test_ambiguous_inverse(self):
        elf = r.Elf64(elf_fixture())
        elf.loads.append(elf.loads[0])
        with self.assertRaises(ValueError):
            elf.virtual_address(512,1)

    def test_bounded_keyword_strings(self):
        result = r.string_candidates(b'\0CropMode\0MovieFrameRate\0XavcFormat\0', maximum=1)
        self.assertEqual(result['crop']['total'],1)
        self.assertEqual(result['recording-format']['total'],2)
        self.assertTrue(result['recording-format']['truncated'])
        self.assertFalse(result['crop']['strings'][0]['is_function_proof'])

    def test_incomplete_or_overlong_not_returned(self):
        self.assertEqual(r.string_candidates(b'CropMode')['crop']['total'],0)
        self.assertEqual(r.string_candidates(b'x'*600+b'CropMode\0')['crop']['total'],0)

    def test_bad_string_bound(self):
        for maximum in (0,101,True):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                r.string_candidates(b'CropMode\0',maximum=maximum)


class BoundaryTests(unittest.TestCase):
    def test_identity_rejected_before_decoder_import(self):
        with patch.dict(sys.modules, {'capstone': None}):
            with self.assertRaisesRegex(ValueError, 'Unrecognized original'):
                r.inspect(b'not a CP', b'not an AP')

    def test_explicit_network_consent(self):
        with self.assertRaises(SystemExit) as caught:
            r.main([])
        self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
