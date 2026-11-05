"""Artificial signed jump-table tests; no firmware or camera access."""
import struct
import unittest
from unittest.mock import patch
import ap_setting_flow as f
from request_trace import Elf64
from test_request_trace import elf_fixture

class SettingFlowTests(unittest.TestCase):
    def test_identity_before_parsing(self):
        with patch.object(f,'Elf64') as parse:
            with self.assertRaises(ValueError):f.inspect(b'not firmware')
            parse.assert_not_called()

    def test_invalid_indices(self):
        for index in (-1,0x263,True,1.0):
            with self.subTest(index=index),self.assertRaises(ValueError):
                f.jump_target(None,index)

    def test_signed_relative_scale(self):
        data=elf_fixture()
        struct.pack_into('<ii',data,600,-4,4)
        with patch.object(f,'JUMP_TABLE',0x1258),patch.object(f,'JUMP_BASE',0x1200):
            self.assertEqual(f.jump_target(Elf64(data),0),0x11f0)
            self.assertEqual(f.jump_target(Elf64(data),1),0x1210)

    def test_unmapped_target_rejected(self):
        data=elf_fixture();struct.pack_into('<i',data,600,0x7fffffff)
        with patch.object(f,'JUMP_TABLE',0x1258),self.assertRaises(ValueError):
            f.jump_target(Elf64(data),0)

if __name__=='__main__':unittest.main()
