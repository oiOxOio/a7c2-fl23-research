"""Read-only, exact-reference AP address and relocation cross-references.

An address materialization is not a function call or proof of movie reachability.
Only narrowly whitelisted ADRP/ADD gaps are joined; unknown instructions stop the trace.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from request_trace import Elf64, AP_SIZE, AP_SHA, check_image, span

TARGET_NAMES = (
    'still_image_size_util::setting_imager_t menu::get_imager_frame_size()',
    'void model::sequence_mode_transition::enter_rec_movie_mode_proc()',
    'void model::sequence_mode_transition::enter_face_registration_mode_proc()',
    'PRM_imager_frame_size',
    'VAL_imager_frame_size_IMAGER_FRAME_SIZE_FULL',
    'VAL_imager_frame_size_IMAGER_FRAME_SIZE_APSC',
    'PRM_HAITA_model_diff_ff_restriction_imager_frame_rate_in_file_format_4k',
    'PRM_HAITA_model_diff_apsc_restriction_imager_frame_rate_in_file_format_4k',
    'PRM_HAITA_setting_menu_shooting_mode_setting_movie_rec_frame_rate_xavc_s_4k_setting_file_format_FEATURE_MANAGER_system_architecture_model_diff_ff_restriction_imager_frame_rate_in_file_format_4k',
    'setting_movie_rec_frame_rate_xavc_s_4k',
    'void infra_wrapper_imaging::detail::set_imager_frame_size(const infra_wrapper_imaging::set_imager_frame_size_in_t&, infra_wrapper_imaging::set_imager_frame_size_out_t&)',
)
WITHDRAWN_STRINGS = (
    (0x53B81A8, 'IsMovieXavcS4K60p'),
    (0x53B81C0, 'IsMovieXavcHS4K60p'),
    (0x53B81D8, 'IsMovieXavcSI4K60p'),
    (0x53C1342, 'movie_rec_frame_rate'),
    (0x54023BF, 'ApscS35mmSel'),
    (0x53CB3FA, 'MENU_ID_APSC_S35_SEL'),
)


def signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def pc_address(word: int, pc: int):
    """Decode ADR/ADRP only. Returned value is a link-time VA, not runtime PC."""
    if word & 0x1f000000 != 0x10000000:
        return None
    imm = signed(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), 21)
    page = bool(word >> 31)
    target = ((pc & ~0xfff) + (imm << 12)) if page else pc + imm
    if not 0 <= target < 1 << 64:
        return None
    return ('adrp' if page else 'adr', word & 31, target)


def add_immediate(word: int):
    """Only 64-bit ADD (immediate), without flags; never ADD Wn or SUB."""
    if word & 0xff800000 != 0x91000000:
        return None
    return (word & 31, (word >> 5) & 31,
            ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0))


def executable_spans(elf: Elf64):
    """Use SHF_EXECINSTR sections, not all bytes in executable PT_LOAD."""
    for sec in elf.sections:
        if sec[1] != 1 or not sec[2] & 4 or not sec[5]:
            continue
        va,off,size=sec[3],sec[4],sec[5]
        if va % 4 or size % 4 or elf.file_offset(va,size) != off:
            raise ValueError('Invalid executable section mapping/alignment.')
        if not any(start <= va and va+size <= start+filesz and perms & 1
                   for start,_,filesz,_,perms in elf.loads):
            raise ValueError('Executable section lacks an executable load mapping.')
        yield va,off,size


def address_xrefs(elf: Elf64, targets: set[int], *, maximum=256) -> dict:
    if type(maximum) is not int or not 1 <= maximum <= 4096:
        raise ValueError('Invalid reference result bound.')
    results = []
    total = 0
    if not targets:
        return dict(total=0, references=[], truncated=False, coverage='No target addresses supplied.')
    seen = set()
    for va, off, size in executable_spans(elf):
        # Only aligned AArch64 words in declared executable sections.
        for delta in range((-va) % 4, size-3, 4):
            pc = va + delta
            word = struct.unpack_from('<I', elf.data, off+delta)[0]
            decoded = pc_address(word, pc)
            if decoded is None or decoded[1] == 31:
                continue
            kind, reg, target = decoded
            length = 4
            if kind == 'adrp':
                match = None
                # Cross only a small whitelist of decoded, non-branching writes
                # to OTHER registers. Unknowns/calls/stores never preserve state.
                for gap in range(1, 5):
                    if delta+gap*4+4 > size:
                        break
                    next_word=struct.unpack_from('<I',elf.data,off+delta+gap*4)[0]
                    add=add_immediate(next_word)
                    if add is not None and add[1] == reg and add[0] != 31:
                        match=(add,gap)
                        break
                    other=pc_address(next_word,pc+gap*4)
                    writes = other[1] if other else add[0] if add else None
                    if writes is not None and writes != reg and writes != 31:
                        continue
                    if next_word == 0xd503201f:  # NOP, no register effects.
                        continue
                    break
                if match is None:
                    continue
                add,gap=match
                target += add[2]
                kind, length = 'bounded_adrp_add', 4*(gap+1)
            if target not in targets or (pc, target) in seen:
                continue
            # Reject overlapping load mappings, even when the bytes agree.
            mapped = elf.file_offset(pc, length)
            if mapped != off+delta:
                raise ValueError('Inconsistent executable mapping.')
            seen.add((pc,target))
            total += 1
            if len(results) < maximum:
                results.append(dict(at=hex(pc), file_offset=hex(mapped), target=hex(target),
                    kind=kind, bytes_count=length,
                    sha256=hashlib.sha256(span(elf.data,mapped,length)).hexdigest(),
                    instruction_boundary_verified=False, runtime_reachable=False))
    return dict(total=total, references=results, truncated=total > len(results),
        coverage='ADR and ADRP/ADD within four instructions across only other ADR/ADRP/ADD writes or NOP; misses other dataflow, GOT and computed references.')


def unsigned_load(word: int):
    """Unsigned-offset LDR X and LDRH W only; no writeback or register offset."""
    opcode=word & 0xffc00000
    if opcode not in (0xf9400000,0x79400000):
        return None
    width=8 if opcode==0xf9400000 else 2
    return (word & 31,(word>>5)&31,((word>>10)&0xfff)*width,width)


def got_pointer_loads(elf: Elf64, slots: set[int]) -> list[dict]:
    """Bounded ADRP/LDR X references to slots, not resolved runtime pointers.

    Cross at most three other simple register writes/loads or NOP. Unknowns,
    calls and stores stop. A load may fault; runtime reachability is not claimed.
    """
    results=[]
    pages={slot & ~4095 for slot in slots}
    for va,off,size in executable_spans(elf):
        for delta in range(0,size,4):
            word=struct.unpack_from('<I',elf.data,off+delta)[0]
            decoded=pc_address(word,va+delta)
            if not decoded or decoded[0]!='adrp' or decoded[1]==31 or decoded[2] not in pages:
                continue
            _,reg,page=decoded
            for gap in range(1,5):
                if delta+gap*4+4>size:break
                next_word=struct.unpack_from('<I',elf.data,off+delta+gap*4)[0]
                load=unsigned_load(next_word)
                if load and load[1]==reg and load[3]==8:
                    slot=page+load[2]
                    if slot in slots:
                        if len(results)>=4096:raise ValueError('GOT reference bound exceeded.')
                        length=(gap+1)*4
                        results.append(dict(at=hex(va+delta),load_at=hex(va+delta+gap*4),
                            slot=hex(slot),destination_register=load[0],
                            sha256=hashlib.sha256(span(elf.data,off+delta,length)).hexdigest(),
                            runtime_pointer_resolved=False,runtime_reachable=False))
                    break
                pc=pc_address(next_word,va+delta+gap*4)
                add=add_immediate(next_word)
                move_zero=(next_word & 0x7f800000 == 0x52800000 and
                           (next_word>>31 or ((next_word>>21)&3)<2))
                dest=(pc[1] if pc else add[0] if add else load[0] if load else
                      next_word & 31 if move_zero else None)
                if dest is not None and dest!=reg and dest!=31:continue
                if next_word==0xd503201f:continue
                break
    return results


def direct_calls(elf: Elf64, targets: set[int]) -> list[dict]:
    """Aligned BL-immediate references only; no indirect calls or function claims."""
    result = []
    for va, off, size in executable_spans(elf):
        for delta in range(0, size, 4):
            word = struct.unpack_from('<I', elf.data, off+delta)[0]
            if word >> 26 != 0x25:
                continue
            target = va + delta + signed(word & 0x3ffffff, 26) * 4
            if target in targets:
                if len(result) >= 4096:
                    raise ValueError('Direct-call result bound exceeded.')
                result.append(dict(at=hex(va+delta), file_offset=hex(off+delta),
                    target=hex(target), kind='bl_immediate',
                    sha256=hashlib.sha256(span(elf.data,off+delta,4)).hexdigest(),
                    runtime_reachable=False))
    return result


def relative_relocations(elf: Elf64, targets: set[int], *, maximum=256) -> dict:
    """SHT_RELA R_AARCH64_RELATIVE only. Symbol relocations are not resolved."""
    result, total = [], 0
    if type(maximum) is not int or not 1 <= maximum <= 4096:
        raise ValueError('Invalid relocation result bound.')
    for sec in elf.sections:
        if sec[1] != 4:
            continue
        off, size, entry = sec[4], sec[5], sec[9]
        if entry != 24 or size % 24 or size // 24 > 4_000_000:
            raise ValueError('Invalid RELA table.')
        for p in range(off, off+size,24):
            slot, info, addend = struct.unpack('<QQq',span(elf.data,p,24))
            if info != 1027 or addend not in targets:
                continue
            # Relative relocation has symbol zero and writes one 64-bit pointer.
            slot_off = elf.file_offset(slot,8)
            total += 1
            if len(result) < maximum:
                result.append(dict(slot=hex(slot), slot_file_offset=hex(slot_off),
                    addend=hex(addend), relocation_file_offset=hex(p),
                    relocation_sha256=hashlib.sha256(span(elf.data,p,24)).hexdigest(),
                    runtime_value='load_bias + addend', code_reference=False))
    return dict(total=total, references=result, truncated=total > len(result))


def imported_slots(elf: Elf64, slots: set[int]) -> list[dict]:
    """Resolve exact R_AARCH64_JUMP_SLOT symbols, not dynamic runtime targets."""
    result = []
    for sec in elf.sections:
        if sec[1] != 4:
            continue
        if sec[9] != 24 or sec[5] % 24:
            raise ValueError('Invalid RELA entry layout.')
        for p in range(sec[4], sec[4]+sec[5], 24):
            slot, info, addend = struct.unpack('<QQq', span(elf.data,p,24))
            if slot not in slots or info & 0xffffffff != 1026:
                continue
            if sec[6] >= len(elf.sections):
                raise ValueError('Invalid relocation symbol-table link.')
            symbols = elf.sections[sec[6]]
            if symbols[1] != 11 or symbols[9] != 24 or symbols[5] % 24:
                raise ValueError('Invalid dynamic symbol table.')
            index = info >> 32
            if index >= symbols[5] // 24 or symbols[6] >= len(elf.sections):
                raise ValueError('Invalid imported symbol index/link.')
            strings = elf.sections[symbols[6]]
            if strings[1] != 3:
                raise ValueError('Invalid dynamic string table.')
            name_offset = struct.unpack('<I',span(elf.data,symbols[4]+index*24,4))[0]
            names = span(elf.data,strings[4],strings[5])
            if name_offset >= len(names):
                raise ValueError('Invalid imported name offset.')
            end = names.find(b'\0',name_offset,min(len(names),name_offset+4097))
            if end < 0:
                raise ValueError('Unterminated imported name.')
            elf.file_offset(slot,8)
            result.append(dict(slot=hex(slot),name=names[name_offset:end].decode('ascii'),
                relocation_file_offset=hex(p),
                relocation_sha256=hashlib.sha256(span(elf.data,p,24)).hexdigest(),
                runtime_target_resolved=False))
    return result


def pointer_words(elf: Elf64, targets: set[int], *, maximum=256) -> dict:
    """Aligned stored pointer candidates in non-executable file-backed segments.

    These may be integers or relocation placeholders, not live pointers. RELA
    evidence is reported separately; no relocation is applied to the input.
    """
    if type(maximum) is not int or not 1 <= maximum <= 4096:
        raise ValueError('Invalid pointer result bound.')
    result, total = [], 0
    for va, off, size, _, flags in elf.loads:
        if flags & 1:
            continue
        for delta in range((-va) % 8, size-7, 8):
            value=struct.unpack_from('<Q',elf.data,off+delta)[0]
            if value not in targets:
                continue
            mapped=elf.file_offset(va+delta,8)
            if mapped != off+delta:
                raise ValueError('Inconsistent pointer mapping.')
            total+=1
            if len(result)<maximum:
                result.append(dict(slot=hex(va+delta), file_offset=hex(mapped),
                    stored_value=hex(value), relocation_applied=False,
                    pointer_semantics_verified=False))
    return dict(total=total,references=result,truncated=total>len(result))


def audit_string_claims(ap: bytes) -> list[dict]:
    """Audit historical prose against actual bytes, not CI status."""
    elf = Elf64(ap)
    result = []
    for off, name in WITHDRAWN_STRINGS:
        needle = name.encode() + b'\0'
        va_offset = elf.file_offset(off, len(needle))
        result.append(dict(claimed_file_offset=hex(off), claimed_text=name,
            exact_bytes_match=span(ap,off,len(needle)) == needle,
            claimed_coordinate_as_va_file_offset=hex(va_offset),
            claimed_coordinate_as_va_match=span(ap,va_offset,len(needle)) == needle,
            ascii_substring_occurrences=ap.count(name.encode()),
            utf16le_occurrences=ap.count(name.encode('utf-16le')),
            utf16be_occurrences=ap.count(name.encode('utf-16be')),
            actual_claimed_span_sha256=hashlib.sha256(span(ap,off,len(needle))).hexdigest()))
    return result


def inspect(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP')
    elf=Elf64(ap)
    targets=[]
    for name in TARGET_NAMES:
        needle=name.encode()+b'\0'
        start=0
        while (pos:=ap.find(needle,start)) >= 0:
            start=pos+1
            if pos and 32 <= ap[pos-1] < 127:
                continue
            va=elf.virtual_address(pos,len(needle))
            targets.append(dict(name=name,file_offset=hex(pos),va=hex(va),
                string_sha256=hashlib.sha256(needle).hexdigest()))
    addresses={int(t['va'],16) for t in targets}
    direct=address_xrefs(elf,addresses,maximum=4096)
    reloc=relative_relocations(elf,addresses,maximum=4096)
    stored=pointer_words(elf,addresses,maximum=4096)
    slots={int(x['slot'],16) for x in reloc['references']+stored['references']}
    indirect=address_xrefs(elf,slots,maximum=4096)
    return dict(schema='a7c2-ap-xrefs/1',ap_sha256=AP_SHA,targets=targets,
        historical_string_claim_audit=audit_string_claims(ap),
        builder_and_wrapper_direct_calls=direct_calls(elf,{0x353deb8,0x34ce4c8}),
        selected_getter_call_leads=[r for r in direct_calls(elf,{0x285d6d0})
            if r['at'] in ('0x1b65120','0x344c840')],
        enum_predicate_registration=relative_relocations(elf,{0x1871eb8}),
        enum_mapping_warning='FULL/APSC name order and predicate comparing value 1 do not establish enum semantics; registration consumer remains undecoded.',
        getter_candidate=dict(va='0x285d6d0',returned_link_time_address='0x7e59d18',
            prefix_sha256=hashlib.sha256(span(ap,elf.file_offset(0x285d6d0,20),20)).hexdigest(),
            runtime_value_unknown=True,full_apsc_enum_values_verified=False),
        transport_imports=imported_slots(elf,{0x5bc2838,0x5bc1308,0x5bc11f8,0x5bc1d70}),
        address_materializations=direct,relative_pointers=reloc,
        stored_pointer_candidates=stored,pointer_slot_address_materializations=indirect,
        camera_io=False,firmware_executed=False,firmware_written=False,
        movie_path_verified=False,recording_verified=False,installable=False,
        warning='Static address references are leads. No function identity, branch reachability, '
                'AP/CP message mapping or sensor timing is established.')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ap',type=Path,required=True,help='Lawful original 2.01 appFw.so; read only.')
    args=parser.parse_args(argv)
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
    from src.video_research.inventory import read_image
    print(json.dumps(inspect(read_image(args.ap)),ensure_ascii=False,indent=2))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
