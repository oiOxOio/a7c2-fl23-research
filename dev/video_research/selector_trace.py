"""Read-only selector investigation on the pinned Sony 2.01 reference.

Direct branch matches are candidates, not proof of instruction boundaries or
runtime ownership. Static analysis is the default. Optional isolated leaf emulation is explicit;
no USB, firmware-file patching or camera installation is provided.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x108000
WINDOWS = (
    ('selector-5002', 0xB2A87C, 0x50),
    ('selector-predicate', 0xB2A8CC, 0x3A),
    ('paired-mode-conversion', 0xB2A04C, 0x130),
    ('mode-index-lookup', 0x98DF72, 0x22),
    ('mode-table-binding', 0x98CCF4, 0x7E),
    ('base-table-constructor', 0x98D878, 0x50),
    ('instance-getter', 0x989D4A, 0x42),
    ('first-mode-query', 0x989E8A, 0x80),
    ('extra-mode-predicate', 0xB0B196, 0x100),
    ('request-submission-wrapper', 0x4A8F0C, 0x38),
    ('configuration-selector-entry', 0x4C0328, 0x270),
    ('descriptor-class-28-branch-unresolved', 0x4C071A, 0x46),
    ('selector-callsite-range', 0x4C09B0, 0x290),
    ('mode-family-choice', 0x4C0F34, 0x150),
    ('format-mode-choice', 0x4BFF90, 0x240),
)
# Some windows are internal ranges, not callable entries; scan only explicit targets.
TARGETS = frozenset((0xB2A87C, 0xB2A8CC, 0xB2A04C, 0x98DF72, 0x98CCF4,
    0x98D878, 0x989D4A, 0x989E8A, 0xB0B196, 0x4A8F0C, 0x4C0328,
    0x4C0F34, 0x4BFF90, 0x989FDA, 0x131888))


def decode_direct_branch(first: int, second: int, address: int):
    """Thumb-2 BL / unconditional B.W only; excludes BLX and conditional B.W."""
    if any(type(x) is not int for x in (first, second, address)):
        raise ValueError('Integer halfwords and address required.')
    if not (0 <= first <= 0xffff and 0 <= second <= 0xffff
            and 0 <= address <= 0xfffffffc and address % 2 == 0):
        raise ValueError('Invalid Thumb halfword or address.')
    if first & 0xf800 != 0xf000 or second & 0xd000 not in (0xd000, 0x9000):
        return None
    sign = (first >> 10) & 1
    i1 = 1 ^ ((second >> 13) & 1) ^ sign
    i2 = 1 ^ ((second >> 11) & 1) ^ sign
    immediate = (sign << 24) | (i1 << 23) | (i2 << 22)
    immediate |= (first & 0x3ff) << 12 | (second & 0x7ff) << 1
    if sign:
        immediate -= 1 << 25
    return ('bl' if second & 0x4000 else 'b.w', (address + 4 + immediate) & 0xffffffff)


def direct_call_candidates(data: bytes, targets: set[int], *, base: int = BASE,
                           maximum: int = 32) -> dict:
    if type(maximum) is not int or not 1 <= maximum <= 1024:
        raise ValueError('Candidate limit must be 1..1024.')
    if type(base) is not int or base < 0 or base % 2 or base + len(data) > 0x100000000:
        raise ValueError('Invalid byte mapping.')
    if not targets or any(type(t) is not int or t < 0 or t > 0xffffffff or t % 2 for t in targets):
        raise ValueError('Nonempty even-address target set required.')
    result = {hex(t): dict(total=0, truncated=False, candidates=[]) for t in sorted(targets)}
    for offset in range(0, len(data) - 3, 2):
        first, second = struct.unpack_from('<HH', data, offset)
        if first & 0xf800 != 0xf000:
            continue
        decoded = decode_direct_branch(first, second, base + offset)
        if decoded is None or decoded[1] not in targets:
            continue
        item = result[hex(decoded[1])]
        item['total'] += 1
        if len(item['candidates']) < maximum:
            item['candidates'].append(dict(at=hex(base+offset), op=decoded[0],
                instruction_boundary_verified=False, reachable_from_movie=False))
        else:
            item['truncated'] = True
    return result


def bounded_ascii(data: bytes, va: int, *, base: int = BASE, maximum: int = 160):
    if type(va) is not int or type(maximum) is not int or not 4 <= maximum <= 512:
        return None
    offset = va - base
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b'\0', offset, min(len(data), offset+maximum+1))
    if end < 0:
        return None
    text = data[offset:end]
    if len(text) < 4 or any(v not in (9, 10, 13) and not 32 <= v < 127 for v in text):
        return None
    return text.decode('ascii')


def inspect(data: bytes) -> dict:
    from mode_trace import CP_SHA, CP_SIZE, file_offset
    if len(data) != CP_SIZE or hashlib.sha256(data).hexdigest() != CP_SHA:
        raise ValueError('Only the pinned original ILCE-7CM2 2.01 CP is accepted.')
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    branches = direct_call_candidates(data, TARGETS)
    windows = []

    def window(label, start, size, *, speculative):
        offset = file_offset(start, size, len(data))
        raw = data[offset:offset+size]
        instructions = list(decoder.disasm_lite(raw, start))
        windows.append(dict(name=label, start=hex(start), bytes_bound=size,
            window_sha256=hashlib.sha256(raw).hexdigest(),
            speculative_start=speculative, extent_is_function_boundary=False,
            decoded_bytes=sum(i[1] for i in instructions),
            instructions=[dict(at=hex(a), size=n, op=op, args=args)
                          for a, n, op, args in instructions]))

    for label, va, size in WINDOWS:
        window(label, va, size, speculative=False)
    for target, result in branches.items():
        for entry in result['candidates'][:6]:
            at = int(entry['at'], 16)
            start = max(BASE, at-48)
            size = min(112, BASE+len(data)-start)
            window('caller-candidate-to-'+target, start, size, speculative=True)
    # A literal entry reference is not a function boundary or a vtable proof.
    pointer_refs = {}
    for va in sorted(TARGETS):
        needle = struct.pack('<I', va | 1)
        hits, cursor, total = [], 0, 0
        while True:
            offset = data.find(needle, cursor)
            if offset < 0:
                break
            cursor = offset + 1
            if offset % 4:
                continue
            total += 1
            if len(hits) < 32:
                hits.append(hex(BASE+offset))
        pointer_refs[hex(va)] = dict(total=total, locations=hits, truncated=total > 32)
    return dict(schema='a7c2-selector-trace/1', cp_sha256=CP_SHA,
        camera_io=False, firmware_executed=False, firmware_written=False,
        movie_path_verified=False, recording_verified=False, installable=False,
        direct_call_candidates=branches, thumb_pointer_candidates=pointer_refs,
        windows=windows)


def emit(report: dict) -> None:
    print(json.dumps({k:v for k,v in report.items() if k != 'windows'}), flush=True)
    for item in report['windows']:
        print(json.dumps(dict(event='selector_window', **{k:v for k,v in item.items()
                           if k != 'instructions'})), flush=True)
        for inst in item['instructions']:
            print('SEL|' + item['name'] + '|' + inst['at'] + '|' +
                  inst['op'] + ' ' + inst['args'], flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-sony-download-terms', action='store_true')
    parser.add_argument('--emulate-selectors', action='store_true',
                        help='Explicitly run three original leaf ranges in isolated emulator RAM.')
    args = parser.parse_args(argv)
    if not args.accept_sony_download_terms:
        parser.error('Explicit Sony-download acceptance is required.')
    import official_reference as official
    sys.path.insert(0, str(ROOT))
    from src.video_research.inventory import inspect_images, read_image
    url, page = official.discover()
    with tempfile.TemporaryDirectory(prefix='a7c2-selector-') as tmp:
        work = Path(tmp)
        work.chmod(0o700)
        source = work/'BODYDATA.DAT'
        with official.open_sony(url) as response, source.open('xb') as output:
            official.trusted_url(response.geturl(), package=True)
            package_sha = official.copy_exact(response, output, official.PACKAGE_SIZE)
        original = official.extract_components(source, work)
        cp, ap = original['files']['cpapp-b.bin'], original['files']['appFw.so']
        inventory = inspect_images(cp, ap)
        if inventory['errors'] or not inventory['cp_layout_verified']:
            raise ValueError('Original inventory failed before selector tracing.')
        print(json.dumps(dict(event='selector_source', page=page,
                              package_sha256=package_sha)), flush=True)
        data = read_image(cp)
        emit(inspect(data))
        if args.emulate_selectors:
            from selector_emulation import run_original
            print(json.dumps(dict(event='isolated_leaf_emulation',
                                  data=run_original(data))), flush=True)
    print('Temporary firmware removed; no camera I/O or firmware-file writes. ' +
          ('Original leaves ran only in isolated emulator RAM.' if args.emulate_selectors
           else 'No firmware instructions were executed.'), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
