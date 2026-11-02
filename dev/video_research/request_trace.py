"""Pinned, read-only AP/CP request investigation. Not an installer.

Table branches are decoded as data, never as a stream of Thumb instructions.
Names and direct-branch matches are leads, not movie-path reachability proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x108000
CP_SIZE = 18_090_880
CP_SHA = 'f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428'
AP_SIZE = 99_960_744
AP_SHA = '2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b'
TARGETS = {0xB2A93A, 0xB2D040, 0x4C0328, 0xB0B074, 0x989D8C}
# Starts are investigation anchors, not a declaration of complete function extents.
WINDOWS = (
    ('instance-getter', 0x989D4A, 10),
    ('availability-dispatch', 0x989E8A, 10),
    ('extra-predicate', 0xB0B196, 70),
    ('descriptor-query-wrapper', 0x989D8C, 112),
    ('previously-claimed-predicate-target', 0xB0B074, 248),
    ('request-generator', 0xB2A93A, 350),
    ('request-context', 0xB2D040, 160),
    ('previously-claimed-request-callsite', 0x48FFC8, 64),
    ('request-submission', 0x4A8F0C, 56),
    ('configuration-dispatch', 0x4C0328, 48),
    ('selector-5002', 0xB2A87C, 80),
    ('selector-predicate', 0xB2A8CC, 58),
)
SYMBOL_GROUPS = {
    'crop': re.compile(r'apsc|super35|super_35|crop', re.I),
    'recording-format': re.compile(r'xavc|movie.*(?:format|framerate|recsetting)|(?:format|framerate).*movie', re.I),
    'sensor-request': re.compile(r'(?:cmos|imager|sensor).*(?:mode|frame|request)|(?:mode|frame).*(?:cmos|imager)', re.I),
}


def span(data: bytes, offset: int, size: int) -> bytes:
    if any(type(x) is not int for x in (offset, size)) or offset < 0 or size < 0:
        raise ValueError('Invalid byte span.')
    if offset > len(data) or size > len(data) - offset:
        raise ValueError('Truncated or out-of-range byte span.')
    return data[offset:offset + size]


def cp_span(data: bytes, address: int, size: int, *, base: int = BASE) -> bytes:
    if any(type(x) is not int for x in (address, base)) or base < 0 or address < base:
        raise ValueError('Invalid CP address.')
    return span(data, address - base, size)


def pc_table(data: bytes, address: int, count: int, *, base: int = BASE) -> dict:
    """Decode bounded PC-based TBB/TBH with caller-reviewed count.

    Thumb PC here is instruction address + 4, including a halfword-aligned
    instruction at address % 4 == 2. Do not align that PC down to a word.
    The supplied count is a reviewed bound, not automatically inferred proof.
    """
    if type(address) is not int or address % 2 or type(count) is not int or not 1 <= count <= 256:
        raise ValueError('Even address and bounded positive count required.')
    first, second = struct.unpack('<HH', cp_span(data, address, 4, base=base))
    if first != 0xE8DF or second & 0xFFE0 != 0xF000 or second & 15 in (13, 15):
        raise ValueError('Expected PC-based TBB/TBH with a valid index register.')
    width = 2 if second & 0x10 else 1
    pc = address + 4
    raw = cp_span(data, pc, count * width, base=base)
    offsets = list(raw) if width == 1 else list(struct.unpack('<' + 'H' * count, raw))
    entries = []
    for index, value in enumerate(offsets):
        target = pc + 2 * value
        if target >= 1 << 32 or target < pc + count * width:
            raise ValueError('Table target overlaps its table or overflows.')
        cp_span(data, target, 2, base=base)
        entries.append(dict(index=index, displacement=value, target=hex(target)))
    return dict(at=hex(address), kind='tbh' if width == 2 else 'tbb',
                index_register='r' + str(second & 15), table=hex(pc), count=count,
                count_source='reviewed caller bound', table_sha256=hashlib.sha256(raw).hexdigest(),
                targets_are_instruction_boundaries=False, entries=entries)


class Elf64:
    """Minimal bounded ELF64 little-endian AArch64 metadata reader (no loading)."""
    def __init__(self, data: bytes):
        self.data = data
        ident = span(data, 0, 16)
        if ident[:7] != b'\x7fELF\x02\x01\x01':
            raise ValueError('Expected little-endian ELF64 version 1.')
        header = struct.unpack('<HHIQQQIHHHHHH', span(data, 16, 48))
        kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
        if kind not in (2, 3) or machine != 183 or version != 1 or ehsize != 64:
            raise ValueError('Unsupported ELF identity.')
        if not 0 < phnum <= 4096 or phsize != 56 or not 0 < shnum <= 65534 or shsize != 64:
            raise ValueError('Unsupported ELF table counts or entry sizes.')
        span(data, phoff, phsize * phnum)
        span(data, shoff, shsize * shnum)
        self.loads = []
        for i in range(phnum):
            typ, perms, off, va, pa, filesz, memsz, align = struct.unpack('<IIQQQQQQ', span(data, phoff+i*56, 56))
            if typ == 1:
                if filesz > memsz or va + memsz > 1 << 64:
                    raise ValueError('Invalid ELF load extent.')
                span(data, off, filesz)
                self.loads.append((va, off, filesz, memsz, perms))
        self.sections = []
        for i in range(shnum):
            sec = struct.unpack('<IIQQQQIIQQ', span(data, shoff+i*64, 64))
            if sec[1] != 8:  # SHT_NOBITS is not file-backed.
                span(data, sec[4], sec[5])
            self.sections.append(sec)

    def file_offset(self, va: int, size: int) -> int:
        if any(type(x) is not int for x in (va, size)) or va < 0 or size <= 0:
            raise ValueError('Invalid ELF virtual span.')
        candidates = []
        for start, off, filesz, _, _ in self.loads:
            if va >= start and va - start <= filesz and size <= filesz - (va - start):
                candidates.append(off + va - start)
        if len(candidates) != 1:
            raise ValueError('ELF virtual span is not uniquely file-backed.')
        return candidates[0]

    def symbols(self):
        for sec in self.sections:
            if sec[1] not in (2, 11):
                continue
            off, size, link, entsize = sec[4], sec[5], sec[6], sec[9]
            if entsize != 24 or size % 24 or size // 24 > 2_000_000 or link >= len(self.sections):
                raise ValueError('Invalid ELF symbol table.')
            strings = self.sections[link]
            if strings[1] != 3:
                raise ValueError('Symbol names must reference a string table.')
            names = span(self.data, strings[4], strings[5])
            for p in range(off, off+size, 24):
                n, info, other, shndx, value, extent = struct.unpack('<IBBHQQ', span(self.data, p, 24))
                if n >= len(names):
                    raise ValueError('Symbol name is outside string table.')
                end = names.find(b'\0', n, min(len(names), n+4097))
                if end < 0:
                    raise ValueError('Missing or overlong symbol-name terminator.')
                name = names[n:end].decode('ascii', errors='backslashreplace')
                if not name or not shndx:
                    continue
                yield dict(name=name, va=value, size=extent, type=info & 15,
                           section=shndx, table_kind=sec[1])


def check_image(data: bytes, size: int, digest: str, name: str) -> None:
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Unrecognized original reference: ' + name)


def inspect(cp: bytes, ap: bytes) -> dict:
    # Check both identities before importing optional disassembly code.
    check_image(cp, CP_SIZE, CP_SHA, 'CP')
    check_image(ap, AP_SIZE, AP_SHA, 'AP')
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from selector_trace import direct_call_candidates
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def window(label, start, size):
        raw = cp_span(cp, start, size)
        insts = []
        for a, n, op, args in decoder.disasm_lite(raw, start):
            insts.append(dict(at=hex(a), size=n, op=op, args=args))
            if op in ('tbb', 'tbh'):
                break  # Inline table bytes must not be presented as instructions.
        return dict(name=label, start=hex(start), bytes_bound=size,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    complete_function=False, movie_reachable=False, instructions=insts)

    windows = [window(*item) for item in WINDOWS]
    tables = [pc_table(cp, 0x4C0354, 29)]
    for target in sorted({int(e['target'], 16) for e in tables[0]['entries']}):
        windows.append(window('configuration-case-'+hex(target), target, 64))
    vtables = []
    for point in (0xDE98A0, 0xDEAC48, 0xDEB10C):
        slots = []
        for slot in (0x10, 0x24, 0xD4, 0x10C, 0x110):
            pointer = struct.unpack('<I', cp_span(cp, point+slot, 4))[0]
            entry = dict(slot=hex(slot), pointer=hex(pointer), thumb=bool(pointer & 1))
            target = pointer & ~1
            if pointer & 1 and BASE <= target < BASE + len(cp) - 128:
                windows.append(window('table-'+hex(point)+'-slot-'+hex(slot), target, 128))
            slots.append(entry)
        vtables.append(dict(address_point=hex(point), runtime_receiver_verified=False, slots=slots))
    elf = Elf64(ap)
    groups = {k:dict(total=0, symbols=[], truncated=False) for k in SYMBOL_GROUPS}
    seen = set()
    for sym in elf.symbols():
        key = (sym['name'], sym['va'], sym['size'])
        if key in seen:
            continue
        seen.add(key)
        for group, pattern in SYMBOL_GROUPS.items():
            if not pattern.search(sym['name']):
                continue
            item = groups[group]
            item['total'] += 1
            if len(item['symbols']) < 80:
                record = dict(sym, va=hex(sym['va']), executable_function=sym['type'] == 2)
                try:
                    record['file_offset'] = hex(elf.file_offset(sym['va'], max(1, sym['size'])))
                except ValueError:
                    record['file_offset'] = None
                item['symbols'].append(record)
            else:
                item['truncated'] = True
    return dict(schema='a7c2-request-trace/1', cp_sha256=CP_SHA, ap_sha256=AP_SHA,
                camera_io=False, firmware_executed=False, firmware_written=False,
                movie_path_verified=False, recording_verified=False, installable=False,
                direct_call_candidates=direct_call_candidates(cp, TARGETS, maximum=16),
                dispatch_tables=tables, vtable_candidates=vtables,
                ap_symbol_candidates=groups, windows=windows)


def emit(report: dict) -> None:
    print(json.dumps({k:v for k,v in report.items() if k != 'windows'}), flush=True)
    for w in report['windows']:
        print(json.dumps(dict(event='request_window', **{k:v for k,v in w.items() if k != 'instructions'})), flush=True)
        for i in w['instructions']:
            print('REQ|'+w['name']+'|'+i['at']+'|'+i['op']+' '+i['args'], flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-sony-download-terms', action='store_true')
    args = parser.parse_args(argv)
    if not args.accept_sony_download_terms:
        parser.error('Explicit Sony download acceptance is required.')
    import official_reference as official
    sys.path.insert(0, str(ROOT))
    from src.video_research.inventory import inspect_images, read_image
    url, page = official.discover()
    with tempfile.TemporaryDirectory(prefix='a7c2-request-') as tmp:
        work = Path(tmp)
        work.chmod(0o700)
        source = work/'BODYDATA.DAT'
        with official.open_sony(url) as response, source.open('xb') as output:
            official.trusted_url(response.geturl(), package=True)
            digest = official.copy_exact(response, output, official.PACKAGE_SIZE)
        original = official.extract_components(source, work)
        cp, ap = original['files']['cpapp-b.bin'], original['files']['appFw.so']
        inventory = inspect_images(cp, ap)
        if inventory['errors'] or not inventory['cp_layout_verified']:
            raise ValueError('Original inventory failed before request tracing.')
        print(json.dumps(dict(event='request_source', page=page, package_sha256=digest)), flush=True)
        emit(inspect(read_image(cp), read_image(ap)))
    print('Temporary firmware removed; static analysis only, no camera I/O.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
