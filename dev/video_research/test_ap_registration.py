"""Artificial condition table only; no firmware, camera or dependencies."""
import struct
import unittest
from unittest.mock import patch
import ap_registration as r
from request_trace import Elf64
from test_request_trace import elf_fixture

class ConditionTests(unittest.TestCase):
    def fixture(self,words):
        data=elf_fixture()
        struct.pack_into('<'+'I'*len(words),data,600,*words)
        return Elf64(data)

    def test_named_pair_and_marker_value(self):
        elf=self.fixture([0x298,0x2955,0x7e4,0x80000001,0x80000000,0x80000001])
        with patch.object(r,'name_at',side_effect=lambda elf,index:dict(index=hex(index))):
            pairs=r.condition_pairs(elf,0x1258)
        self.assertEqual(len(pairs),2)
        self.assertEqual(pairs[0]['value_name']['index'],'0x2955')
        self.assertIsNone(pairs[1]['value_name'])
        self.assertIs(pairs[1]['marker_semantics_verified'],False)

    def test_invalid_end_marker(self):
        with self.assertRaises(ValueError):
            r.condition_pairs(self.fixture([0x80000000,0]),0x1258)

    def test_invalid_property_or_value(self):
        for pair in ([65536,0],[1,0x80000002]):
            with self.subTest(pair=pair),self.assertRaises(ValueError):
                r.condition_pairs(self.fixture(pair),0x1258)

    def test_missing_terminator_is_not_silently_truncated(self):
        with patch.object(r,'name_at',return_value={}),self.assertRaises(ValueError):
            r.condition_pairs(self.fixture([1,2]),0x1258)

if __name__=='__main__':unittest.main()
