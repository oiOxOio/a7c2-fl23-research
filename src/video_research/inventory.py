"""Bounded, read-only inventory of an exact supported CP reference image.

Descriptor reconstruction follows the pinned MIT research in NOTICE.txt.
This parses stored tables only; it does not run code or establish wire values.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct

from . import reference as ref

MAX_IMAGE_BYTES = 128 * 1024 * 1024


class LayoutError(ValueError):
    """The reference layout could not be decoded without guessing."""


def read_image(path: Path) -> bytes:
    """Read one regular local file; do not follow a final symlink or a device."""
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Input must be a regular file, not a symlink or device.')
    if not 0 < before.st_size <= MAX_IMAGE_BYTES:
        raise ValueError('Input size must be between 1 byte and 128 MiB.')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError('Input changed to a non-regular file.')
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if identity(before) != identity(opened):
            raise ValueError('Input changed before reading; no analysis performed.')
        data = stream.read(MAX_IMAGE_BYTES + 1)
        after = os.fstat(stream.fileno())
        if identity(opened) != identity(after) or len(data) != opened.st_size:
            raise ValueError('Input changed while reading; no analysis performed.')
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError('Input exceeds the offline size limit.')
    return data


def fingerprint(data: bytes, spec: ref.ImageSpec) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    matches = len(data) == spec.size and digest == spec.sha256
    return dict(component=spec.name, size=len(data), sha256=digest,
                reference_size=spec.size, reference_sha256=spec.sha256,
                status='matched' if matches else 'unsupported_reference')


@dataclass(frozen=True)
class Mode:
    index: int
    mode_id: int
    width: int
    height: int
    column: int
    commands: dict[int, int]

    def summary(self) -> dict:
        return dict(index=self.index, mode_id=f'0x{self.mode_id:04x}',
                    width=self.width, height=self.height, patch_column=self.column,
                    command_count=len(self.commands), command_0001=self.commands.get(1),
                    frame_record_file_offset=hex(ref.FRAME_TABLE_VA-ref.CP_BASE+
                                                 self.index*ref.FRAME_STRIDE))


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def unpack(self, fmt: str, va: int):
        offset = va - ref.CP_BASE
        size = struct.calcsize(fmt)
        if offset < 0 or offset > len(self.data) - size:
            raise LayoutError(f'CP VA {va:#x} is outside the file-backed image.')
        return struct.unpack_from(fmt, self.data, offset)[0]

    def u16(self, va: int) -> int:
        return self.unpack('<H', va)

    def u32(self, va: int) -> int:
        return self.unpack('<I', va)

    def u8(self, va: int) -> int:
        return self.unpack('<B', va)


def _parse_cp(data: bytes) -> tuple[Mode, ...]:
    """Structural decoder; production callers MUST fingerprint before entering.

    Kept private so tests can use synthetic, non-Sony tables without adding a
    CLI bypass of the fixed reference identity. Later writes may override the
    staged command map; duplicate command IDs follow the reference's last-write
    semantics, not a presumed one-ID/one-descriptor invariant.
    """
    image = _Reader(data)
    modes = tuple(image.u32(ref.MODE_IDS_VA+i*4) for i in range(len(ref.MODE_IDS)))
    if modes != ref.MODE_IDS:
        raise LayoutError('Mode IDs/order differ from the pinned 2.01 reference.')
    base = {}
    for i in range(ref.DESCRIPTOR_COUNT):
        descriptor = image.u32(ref.DESCRIPTOR_TABLE_VA+i*4)
        base[image.u16(descriptor)] = image.u8(descriptor+2)
    patches = []
    for i in range(ref.PATCH_COUNT):
        row = ref.PATCH_TABLE_VA+i*ref.PATCH_STRIDE
        descriptor = image.u32(row)-2
        command = image.u16(descriptor)
        values = tuple(image.u8(row+4+c) for c in range(ref.COLUMN_COUNT))
        patches.append((command, values))
    result = []
    for i, mode in enumerate(modes):
        column = image.u32(ref.COLUMN_TABLE_VA+i*4)
        if column >= ref.COLUMN_COUNT:
            raise LayoutError('Mode patch column is outside the 18-column table.')
        row = ref.FRAME_TABLE_VA+i*ref.FRAME_STRIDE
        width, height = image.u16(row+8), image.u16(row+0x1A)
        commands = dict(base)
        for command, values in patches:
            commands[command] = values[column]
        result.append(Mode(i, mode, width, height, column, commands))
    return tuple(result)


def command_diff(before: Mode, after: Mode) -> list[int]:
    return sorted(k for k in before.commands.keys() | after.commands.keys()
                  if before.commands.get(k) != after.commands.get(k))


def _crosscheck(modes: tuple[Mode, ...]) -> None:
    by_id = {m.mode_id: m for m in modes}
    for mid, dimensions in ref.FRAME_CHECKS.items():
        m = by_id[mid]
        if (m.width, m.height) != dimensions:
            raise LayoutError(f'Published frame cross-check failed for {mid:#x}.')
    for mid, value in ref.COMMAND_CHECKS.items():
        if by_id[mid].commands.get(1) != value:
            raise LayoutError(f'Published command-0001 cross-check failed for {mid:#x}.')
    for before, after, expected in ref.DIFF_CHECKS:
        if set(command_diff(by_id[before], by_id[after])) != expected:
            raise LayoutError('Published staged-command difference cross-check failed.')


def inspect_images(cp_path: Path | None = None, ap_path: Path | None = None) -> dict:
    report = dict(schema='a7c2-video-inventory/1', model=ref.MODEL,
                  firmware=ref.FIRMWARE, sources=list(ref.SOURCES),
                  boundaries=ref.boundaries(), images={}, modes=[], differences=[],
                  cp_layout_verified=False, errors=[])
    for key, path, spec in (('cp', cp_path, ref.CP), ('ap', ap_path, ref.AP)):
        if path is None:
            continue
        data = read_image(path)
        record = fingerprint(data, spec)
        report['images'][key] = record
        if record['status'] != 'matched':
            report['errors'].append(key + ': unsupported reference; offsets were NOT parsed. '
                'Use your lawful original 2.01 component, not an FL23/custom image. '
                'This does not imply the existing camera modifications are invalid.')
            continue
        if key == 'ap':
            if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
                record['status'] = 'invalid_layout'
                report['errors'].append('AP is not a little-endian AArch64 ELF.')
            continue
        try:
            modes = _parse_cp(data)
            _crosscheck(modes)
        except LayoutError as exc:
            record['status'] = 'invalid_layout'
            report['errors'].append(str(exc))
            continue
        by_id = {m.mode_id: m for m in modes}
        report['modes'] = [m.summary() for m in modes]
        report['differences'] = [
            dict(before=f'0x{before:04x}', after=f'0x{after:04x}',
                 changed_command_ids=[f'0x{k:04x}' for k in command_diff(by_id[before], by_id[after])])
            for before, after, _ in ref.DIFF_CHECKS]
        report['cp_layout_verified'] = True
    report['status'] = 'input_rejected' if report['errors'] else (
        'offline_inventory_complete' if report['images'] else 'no_inputs')
    report['scope'] = ('Stored table reconstruction only. No physical sensor-register semantics, '
                       'runtime callflow, frame cadence, or captured field of view is established.')
    return report
