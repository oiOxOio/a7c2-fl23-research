"""Bounded static CP mode-selection exploration; never executes firmware.

The scan is deliberately labelled candidate-only: halfword alignment does not
prove an instruction boundary, a function or a runtime caller. Capstone is an
optional development dependency, never imported by the offline production CLI.
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
CP_SHA = 'f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428'
CP_SIZE = 18090880
# Published entry points, not independently proven function extents.
WINDOWS = (
    ('frame-record-consumer', 0x131888, 0x300),
    ('SetModeAsync', 0x989fda, 0x3a),
    ('SetModeAsync-preparation', 0x98ac02, 0x3c),
    ('mode-lookup-candidate', 0x98bd00, 0x150),
    ('outer-slot-24', 0x98cfde, 0xa),
    ('outer-slot-10c', 0x39affc, 0x100),
    ('mode-column-selection', 0x98c806, 0x30),
    ('descriptor-consumption', 0x98bf52, 0x6e),
)


def file_offset(va: int, size: int, length: int) -> int:
    if not isinstance(va, int) or not isinstance(size, int) or size <= 0:
        raise ValueError('Invalid file-backed window.')
    offset = va - BASE
    if offset < 0 or offset > length - size:
        raise ValueError('Window lies outside the CP file mapping.')
    return offset


def decode_mov_halfwords(first: int, second: int):
    """Decode just Thumb-2 MOVW/MOVT immediates, not surrounding code."""
    if not 0 <= first <= 0xffff or not 0 <= second <= 0xffff or second & 0x8000:
        return None
    kind = first & 0xfbf0
    if kind not in (0xf240, 0xf2c0):
        return None
    register = (second >> 8) & 15
    if register == 15:
        return None
    value = ((first & 15) << 12) | (((first >> 10) & 1) << 11)
    value |= ((second >> 12) & 7) << 8 | (second & 255)
    return ('movw' if kind == 0xf240 else 'movt', register, value)


def immediate_candidates(data: bytes, values: set[int], maximum: int = 128):
    if maximum < 1:
        raise ValueError('Candidate bound must be positive.')
    found, total = [], 0
    for offset in range(0, len(data) - 3, 2):
        first, second = struct.unpack_from('<HH', data, offset)
        decoded = decode_mov_halfwords(first, second)
        if decoded and decoded[0] == 'movw' and decoded[2] in values:
            total += 1
            if len(found) < maximum:
                found.append(dict(cp_va=hex(BASE+offset), file_offset=hex(offset),
                                  register=decoded[1], value=hex(decoded[2]),
                                  instruction_boundary_verified=False))
    return dict(total=total, truncated=total > maximum, candidates=found)


def pointer_table_candidates(data: bytes, slots: dict[int, int], maximum: int = 16) -> dict:
    """Find exact co-located slots; this does NOT prove a live object's vptr.

    Slot values include Thumb state bits. Returned roots are possible vtable
    address points, not ELF symbols or an assertion of runtime ownership.
    """
    if not slots or maximum < 1:
        raise ValueError('A nonempty bounded slot pattern is required.')
    if any(not isinstance(k, int) or k < 0 or k % 4 or
           not isinstance(v, int) or not 0 <= v <= 0xffffffff
           for k, v in slots.items()):
        raise ValueError('Slots must be aligned nonnegative offsets with u32 values.')
    first = min(slots)
    needle = struct.pack('<I', slots[first])
    cursor, total, tables = 0, 0, []
    while True:
        hit = data.find(needle, cursor)
        if hit < 0:
            break
        cursor = hit + 1
        root = hit - first
        if root < 0 or root % 4 or root > len(data) - max(slots) - 4:
            continue
        if not all(struct.unpack_from('<I', data, root+k)[0] == v for k, v in slots.items()):
            continue
        total += 1
        if len(tables) < maximum:
            tables.append(dict(cp_va=hex(BASE+root), file_offset=hex(root),
                slots={hex(k): hex(v) for k, v in sorted(slots.items())},
                runtime_receiver_verified=False))
    return dict(total=total, truncated=total > maximum, candidates=tables)


def emit_trace(report: dict) -> None:
    """Readable bounded instruction lines, avoiding thousands of JSON log lines."""
    for category in ('windows', 'candidate_contexts'):
        for item in report[category]:
            label = item.get('name', item['cp_va'])
            print(json.dumps(dict(event=category, **{k:v for k,v in item.items()
                                                      if k != 'instructions'})), flush=True)
            for inst in item['instructions']:
                print('CP|' + label + '|' + inst['at'] + '|' +
                      inst['op'] + ' ' + inst['args'], flush=True)
    print(json.dumps({k:v for k,v in report.items() if k not in
                      ('windows', 'candidate_contexts')}), flush=True)


def inspect(data: bytes) -> dict:
    if len(data) != CP_SIZE or hashlib.sha256(data).hexdigest() != CP_SHA:
        raise ValueError('Only the pinned original ILCE-7CM2 2.01 CP is accepted.')
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    report = dict(schema='a7c2-mode-trace/1', cp_sha256=CP_SHA,
                  camera_io=False, firmware_executed=False, firmware_written=False,
                  runtime_callflow_verified=False, recording_verified=False,
                  installable=False, windows=[], candidate_contexts=[])
    for name, va, size in WINDOWS:
        offset = file_offset(va, size, len(data))
        instructions = list(decoder.disasm(data[offset:offset+size], va))
        report['windows'].append(dict(name=name, cp_va=hex(va), size_bound=size,
            sha256=hashlib.sha256(data[offset:offset+size]).hexdigest(),
            extent_is_function_boundary=False,
            instructions=[dict(at=hex(i.address), op=i.mnemonic, args=i.op_str)
                          for i in instructions[:192]]))
    candidates = immediate_candidates(data, {0x5002, 0x99d4, 0x01d6, 0xe8e0})
    report['immediate_candidates'] = candidates
    for entry in candidates['candidates']:
        if entry['value'] != '0x5002':
            continue
        va = int(entry['cp_va'], 16)
        start = max(BASE, va-16)
        offset = file_offset(start, 80, len(data))
        instructions = list(decoder.disasm(data[offset:offset+80], start))
        report['candidate_contexts'].append(dict(cp_va=hex(va),
            warning='Speculative halfword-aligned context; not a reachable-code proof.',
            instructions=[dict(at=hex(i.address), op=i.mnemonic, args=i.op_str)
                          for i in instructions]))
    report['co_located_slot_candidates'] = pointer_table_candidates(data, {
        0x24: 0x98cfdf, 0x10c: 0x39affd, 0x110: 0x98c807})
    report['mode_column_semantics'] = {
        'input_domain': 'index into mode-column table, NOT literal sensor mode ID',
        'function_va': '0x98c806', 'mode_column_table_va': '0x10fe8e0',
        'patch_table_va': '0x10fdcb0', 'patch_row_stride': 24,
        'terminator': 'zero target pointer',
        'runtime_sensor_write_verified': False}
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-sony-download-terms', action='store_true')
    args = parser.parse_args(argv)
    if not args.accept_sony_download_terms:
        parser.error('Explicit Sony-download acceptance is required.')
    import official_reference as official
    sys.path.insert(0, str(ROOT))
    from src.video_research.inventory import inspect_images, read_image
    url, page = official.discover()
    with tempfile.TemporaryDirectory(prefix='a7c2-mode-trace-') as tmp:
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
            raise ValueError('Original inventory failed before mode tracing.')
        print(json.dumps(dict(event='mode_trace_source', page=page,
                              package_sha256=package_sha, modes=inventory['modes'])), flush=True)
        report = inspect(read_image(cp))
        emit_trace(report)
    print('Temporary original firmware removed; no device access or firmware execution.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
