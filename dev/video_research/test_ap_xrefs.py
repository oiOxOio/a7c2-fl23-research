"""Synthetic AArch64/ELF cases, no firmware, network or camera."""
import struct
import unittest
from unittest.mock import patch
import ap_xrefs as x
from request_trace import Elf64
from test_request_trace import elf_fixture


def adr(pc,target,rd=0,page=False):
    displacement=((target & ~4095)-(pc & ~4095))//4096 if page else target-pc
    imm=displacement & ((1<<21)-1)
    return (0x90000000 if page else 0x10000000) | ((imm & 3)<<29) | ((imm>>2)<<5) | rd


def add(rd,rn,imm):
    return 0x91000000 | (imm<<10) | (rn<<5) | rd


def fixture(words):
    data=elf_fixture()
    for i,w in enumerate(words):
        struct.pack_into('<I',data,512+4*i,w)
    elf=Elf64(data)
    elf.sections.append((0,1,6,0x1200,512,128,0,0,4,0))
    return elf


class DecodeTests(unittest.TestCase):
    def test_adr_positive_negative(self):
        for delta in (-100,0,100,(1<<20)-1,-(1<<20)):
            self.assertEqual(x.pc_address(adr(0x200000,0x200000+delta,3),0x200000),('adr',3,0x200000+delta))

    def test_adrp_pages_and_negative(self):
        for target in (0x1000,0x3000,0x1ff000):
            self.assertEqual(x.pc_address(adr(0x2018,target,4,True),0x2018),('adrp',4,target))

    def test_other_instruction_rejected(self):
        for word in (0,0xd503201f,0xd65f03c0,0x91000000):
            self.assertIsNone(x.pc_address(word,0x1000))

    def test_add_64_no_flags(self):
        self.assertEqual(x.add_immediate(add(3,5,123)),(3,5,123))
        self.assertEqual(x.add_immediate(add(3,5,123)|(1<<22)),(3,5,123<<12))
        for word in (0x11000000,0xb1000000,0xd1000000,0x91800000):
            self.assertIsNone(x.add_immediate(word))

    def test_address_underflow(self):
        self.assertIsNone(x.pc_address(adr(4,-4),4))


class XrefTests(unittest.TestCase):
    def test_direct_call_positive_negative_and_not_b(self):
        elf=fixture([0x94000004,0x97ffffff,0x14000002])
        hits=x.direct_calls(elf,{0x1210,0x1200})
        self.assertEqual([(r['at'],r['target']) for r in hits],
                         [('0x1200','0x1210'),('0x1204','0x1200')])
        self.assertTrue(all(not r['runtime_reachable'] for r in hits))

    def test_direct_adr(self):
        report=x.address_xrefs(fixture([adr(0x1200,0x1290)]),{0x1290})
        self.assertEqual(report['total'],1)
        self.assertEqual(report['references'][0]['at'],'0x1200')
        self.assertFalse(report['references'][0]['runtime_reachable'])

    def test_adjacent_pair_with_different_destination(self):
        elf=fixture([adr(0x1200,0x1000,3,True),add(2,3,0x290)])
        report=x.address_xrefs(elf,{0x1290})
        self.assertEqual(report['total'],1)
        self.assertEqual(report['references'][0]['bytes_count'],8)

    def test_mismatch_or_nonadjacent_not_joined(self):
        for words in ([adr(0x1200,0x1000,3,True),add(2,4,0x290)],
                      [adr(0x1200,0x1000,3,True),0x94000000,add(2,3,0x290)]):
            self.assertEqual(x.address_xrefs(fixture(words),{0x1290})['total'],0)

    def test_interleaved_other_adrp_preserves_base(self):
        elf=fixture([adr(0x1200,0x1000,3,True),adr(0x1204,0x9000,5,True),add(2,3,0x290)])
        self.assertEqual(x.address_xrefs(elf,{0x1290})['total'],1)

    def test_base_clobber_stops_trace(self):
        elf=fixture([adr(0x1200,0x1000,3,True),adr(0x1204,0x9000,3,True),add(2,3,0x290)])
        self.assertEqual(x.address_xrefs(elf,{0x1290})['total'],0)

    def test_non_executable_not_scanned(self):
        elf=fixture([adr(0x1200,0x1290)])
        elf.loads=[(*elf.loads[0][:4],4)]
        with self.assertRaises(ValueError): x.address_xrefs(elf,{0x1290})

    def test_register31_excluded(self):
        elf=fixture([adr(0x1200,0x1290,31)])
        self.assertEqual(x.address_xrefs(elf,{0x1290})['total'],0)

    def test_truncation_explicit(self):
        elf=fixture([adr(0x1200,0x1290),adr(0x1204,0x1290)])
        report=x.address_xrefs(elf,{0x1290},maximum=1)
        self.assertEqual(report['total'],2)
        self.assertTrue(report['truncated'])

    def test_ambiguous_mapping_rejected(self):
        elf=fixture([adr(0x1200,0x1290)])
        elf.loads.append(elf.loads[0])
        with self.assertRaises(ValueError):
            x.address_xrefs(elf,{0x1290})

    def test_bounds(self):
        for value in (0,True,4097):
            with self.assertRaises(ValueError):
                x.address_xrefs(fixture([]),set(),maximum=value)


class RelocationTests(unittest.TestCase):
    def fixture(self,info=1027,addend=0x1290):
        elf=fixture([])
        data=bytearray(elf.data)
        struct.pack_into('<QQq',data,600,0x1280,info,addend)
        elf.data=bytes(data)
        elf.sections.append((0,4,0,0,600,24,0,0,8,24))
        return elf

    def test_relative_pointer(self):
        report=x.relative_relocations(self.fixture(),{0x1290})
        self.assertEqual(report['total'],1)
        self.assertEqual(report['references'][0]['slot'],'0x1280')

    def test_symbol_and_other_reloc_not_guessed(self):
        for info in ((1<<32)|1027,257):
            self.assertEqual(x.relative_relocations(self.fixture(info),{0x1290})['total'],0)

    def test_negative_addend_not_unsigned(self):
        self.assertEqual(x.relative_relocations(self.fixture(addend=-1),{(1<<64)-1})['total'],0)

    def test_unbacked_slot_rejected(self):
        elf=self.fixture()
        data=bytearray(elf.data);struct.pack_into('<Q',data,600,0x1300);elf.data=data
        with self.assertRaises(ValueError): x.relative_relocations(elf,{0x1290})

    def test_invalid_entry(self):
        elf=self.fixture();elf.sections[-1]=(*elf.sections[-1][:-1],16)
        with self.assertRaises(ValueError): x.relative_relocations(elf,{0x1290})

    def test_reference_identity_before_parse(self):
        with patch.object(x,'Elf64') as parse:
            with self.assertRaises(ValueError): x.inspect(b'not firmware')
            parse.assert_not_called()

class GotLoadTests(unittest.TestCase):
    @staticmethod
    def load(rd,rn,offset,width=8):
        return (0xf9400000 if width==8 else 0x79400000) | ((offset//width)<<10) | (rn<<5) | rd

    def test_load_decoder(self):
        self.assertEqual(x.unsigned_load(self.load(2,3,0x2f8)),(2,3,0x2f8,8))
        self.assertEqual(x.unsigned_load(self.load(0,4,2,2)),(0,4,2,2))
        self.assertIsNone(x.unsigned_load(0xf9000000))

    def test_got_adjacent(self):
        r=x.got_pointer_loads(fixture([adr(0x1200,0x1000,3,True),self.load(2,3,0x280)]),{0x1280})
        self.assertEqual(r[0]['slot'],'0x1280')
        self.assertIs(r[0]['runtime_pointer_resolved'],False)

    def test_cross_movz_and_halfword_other_register(self):
        words=[adr(0x1200,0x1000,3,True),0xd2801404,self.load(0,5,0,2),self.load(2,3,0x280)]
        self.assertEqual(len(x.got_pointer_loads(fixture(words),{0x1280})),1)

    def test_no_cross_call_store_or_clobber(self):
        for word in (0x94000000,0xf9000000,0xd2801403,self.load(3,5,0,2)):
            with self.subTest(word=word):
                words=[adr(0x1200,0x1000,3,True),word,self.load(2,3,0x280)]
                self.assertEqual(x.got_pointer_loads(fixture(words),{0x1280}),[])

    def test_halfword_is_not_pointer_load(self):
        words=[adr(0x1200,0x1000,3,True),self.load(2,3,0x280,2)]
        self.assertEqual(x.got_pointer_loads(fixture(words),{0x1280}),[])


class ImportTests(unittest.TestCase):
    def fixture(self, info=(1 << 32) | 1026):
        elf=Elf64(elf_fixture())
        data=bytearray(elf.data)
        struct.pack_into('<QQq',data,600,0x1280,info,0)
        elf.data=data
        elf.sections.append((0,4,0,0,600,24,2,0,8,24))
        return elf

    def test_jump_slot_name_not_runtime_target(self):
        result=x.imported_slots(self.fixture(),{0x1280})
        self.assertEqual(result[0]['name'],'MovieFormat')
        self.assertIs(result[0]['runtime_target_resolved'],False)

    def test_relative_not_an_import(self):
        self.assertEqual(x.imported_slots(self.fixture(1027),{0x1280}),[])

    def test_bad_symbol_index(self):
        with self.assertRaises(ValueError):
            x.imported_slots(self.fixture((2 << 32) | 1026),{0x1280})

    def test_bad_table_link(self):
        elf=self.fixture()
        sec=list(elf.sections[-1]);sec[6]=99;elf.sections[-1]=tuple(sec)
        with self.assertRaises(ValueError): x.imported_slots(elf,{0x1280})

    def test_bad_name(self):
        elf=self.fixture();struct.pack_into('<I',elf.data,504,15)
        with self.assertRaises(ValueError): x.imported_slots(elf,{0x1280})


class PointerTests(unittest.TestCase):
    def fixture(self):
        elf=fixture([])
        elf.loads=[(*elf.loads[0][:4],6)]
        data=bytearray(elf.data)
        struct.pack_into('<Q',data,600,0x1290)
        elf.data=bytes(data)
        return elf

    def test_aligned_stored_candidate(self):
        r=x.pointer_words(self.fixture(),{0x1290})
        self.assertEqual(r['total'],1)
        self.assertFalse(r['references'][0]['pointer_semantics_verified'])

    def test_executable_segment_excluded(self):
        elf=self.fixture();elf.loads=[(*elf.loads[0][:4],5)]
        self.assertEqual(x.pointer_words(elf,{0x1290})['total'],0)

    def test_invalid_limit(self):
        with self.assertRaises(ValueError): x.pointer_words(self.fixture(),{0x1290},maximum=True)

if __name__=='__main__': unittest.main()
