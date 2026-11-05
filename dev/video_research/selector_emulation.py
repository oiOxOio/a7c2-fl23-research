"""Isolated original-Thumb leaf tests, NOT camera or full-firmware emulation.

Only three reviewed leaf ranges can execute. Original tables are read-only;
only declared staged descriptor bytes may be written in emulator RAM. No USB,
MMIO mapping, firmware-file writes, opaque helper stubs or install entrypoint.
"""
from __future__ import annotations
import hashlib
import struct

BASE = 0x108000
CP_SIZE = 18090880
CP_SHA = 'f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428'
MODE_TABLE, COLUMN_TABLE, PATCH_TABLE = 0xDE99D4, 0x10FE8E0, 0x10FDCB0
MODE_COUNT, PATCH_COUNT = 30, 129
OBJECT, STOP = 0x20000000, 0x30000000
LEAVES = {
    'lookup': (0x98DF72, 0x98DF94),
    'paired_mode': (0xB2A04C, 0xB2A17C),
    'stage_column': (0x98C806, 0x98C836),
}
PAIRS = {
    0x5000: 0x5001, 0x5002: 0x5004, 0x5003: 0x5005,
    0x5020: 0x5021, 0x5022: 0x5024, 0x5023: 0x5025,
    0x5200: 0x5201, 0x5202: 0x5204, 0x5203: 0x5205,
    0x5220: 0x5221, 0x5222: 0x5224, 0x5223: 0x5225,
    0x5400: 0x5401, 0x5402: 0x5404, 0x5403: 0x5405,
    0x5420: 0x5421, 0x5422: 0x5424, 0x5423: 0x5425,
}


def u32(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError('An unsigned 32-bit integer is required.')
    return value


def paired_mode(flag: int, mode: int) -> int:
    u32(flag)
    u32(mode)
    # Important: the original converter compares flag == 1, not flag != 0.
    return PAIRS.get(mode, mode) if flag == 1 else mode


def mode_index(modes: tuple[int, ...], mode: int) -> int:
    u32(mode)
    if len(modes) > 255 or any(type(x) is not int or not 0 <= x <= 0xffffffff for x in modes):
        raise ValueError('The bounded model accepts at most 255 u32 mode IDs.')
    return modes.index(mode) if mode in modes else 0xff


def require_original(data: bytes) -> None:
    if len(data) != CP_SIZE or hashlib.sha256(data).hexdigest() != CP_SHA:
        raise ValueError('Only the pinned original ILCE-7CM2 2.01 CP is accepted.')


def image_slice(data: bytes, va: int, size: int) -> bytes:
    if type(va) is not int or type(size) is not int:
        raise ValueError('Integer address and length required.')
    offset = va - BASE
    if size < 1 or offset < 0 or offset+size > len(data):
        raise ValueError('Original-image slice is out of bounds.')
    return data[offset:offset+size]


def run_original(data: bytes) -> dict:
    # Identity is checked before importing the optional instruction emulator.
    require_original(data)
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_PROT_READ,
                         UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_WRITE)
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
    modes = struct.unpack('<30I', image_slice(data, MODE_TABLE, 120))
    columns = struct.unpack('<30I', image_slice(data, COLUMN_TABLE, 120))
    if len(set(modes)) != MODE_COUNT or any(c >= 18 for c in columns):
        raise ValueError('Unexpected mode table layout.')
    rows = [image_slice(data, PATCH_TABLE+i*24, 24) for i in range(PATCH_COUNT)]
    targets = [struct.unpack_from('<I', row)[0] for row in rows]
    if not all(targets) or struct.unpack('<I', image_slice(data, PATCH_TABLE+PATCH_COUNT*24, 4))[0] != 0:
        raise ValueError('Unexpected staged-table terminator.')
    for address in targets:
        image_slice(data, address, 1)
    target_set = set(targets)

    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    permissions = {}

    def pages(va, size, rights):
        image_slice(data, va, size)
        for page in range(va & ~0xfff, (va+size+0xfff) & ~0xfff, 4096):
            permissions[page] = permissions.get(page, 0) | rights

    for start, end in LEAVES.values():
        pages(start, end-start, UC_PROT_READ | UC_PROT_EXEC)
    pages(MODE_TABLE, 120, UC_PROT_READ)
    pages(COLUMN_TABLE, 120, UC_PROT_READ)
    pages(PATCH_TABLE, (PATCH_COUNT+1)*24, UC_PROT_READ)
    for address in targets:
        pages(address, 1, UC_PROT_READ | UC_PROT_WRITE)
    if any(rights & UC_PROT_EXEC and rights & UC_PROT_WRITE for rights in permissions.values()):
        raise ValueError('Writable and executable original pages must remain separate.')
    for page, rights in sorted(permissions.items()):
        machine.mem_map(page, 4096, rights)
        offset = page-BASE
        machine.mem_write(page, data[offset:min(offset+4096, len(data))])
    machine.mem_map(OBJECT, 4096, UC_PROT_READ)
    machine.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    state = {'leaf': None, 'instructions': 0, 'writes': [], 'error': None}

    def instruction_hook(uc, address, size, _):
        start, end = LEAVES[state['leaf']]
        if not start <= address < address+size <= end:
            state['error'] = 'Execution escaped the selected leaf.'
            uc.emu_stop()
        state['instructions'] += 1

    def write_hook(uc, _access, address, size, value, _):
        if state['leaf'] != 'stage_column' or size != 1 or address not in target_set:
            state['error'] = 'Write escaped declared staged bytes.'
            uc.emu_stop()
        else:
            state['writes'].append((address, value & 0xff))

    machine.hook_add(UC_HOOK_CODE, instruction_hook)
    machine.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    registers = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12)

    def invoke(leaf, r0, r1, *, count=MODE_COUNT):
        state.update(leaf=leaf, instructions=0, writes=[], error=None)
        machine.mem_write(OBJECT, struct.pack('<III', 0, count, MODE_TABLE))
        for register in registers:
            machine.reg_write(register, 0)
        machine.reg_write(UC_ARM_REG_CPSR, 0x30)  # Thumb, user mode; no interrupts.
        machine.reg_write(UC_ARM_REG_SP, OBJECT+0x800)
        machine.reg_write(UC_ARM_REG_LR, STOP | 1)
        machine.reg_write(UC_ARM_REG_R0, r0)
        machine.reg_write(UC_ARM_REG_R1, r1)
        machine.emu_start(LEAVES[leaf][0] | 1, STOP, timeout=200000, count=4096)
        if state['error'] or machine.reg_read(UC_ARM_REG_PC) != STOP:
            raise ValueError(state['error'] or 'Leaf did not return within limits.')
        if machine.reg_read(UC_ARM_REG_SP) != OBJECT+0x800:
            raise ValueError('Leaf unexpectedly changed the stack pointer.')
        return machine.reg_read(UC_ARM_REG_R0), list(state['writes']), state['instructions']

    lookup_results = []
    for mode in (*modes, 0, 1, 0xffffffff):
        result, writes, _ = invoke('lookup', OBJECT, mode)
        if result != mode_index(modes, mode) or writes:
            raise ValueError('Original mode lookup differs from the reviewed model.')
        lookup_results.append({'mode': hex(mode), 'index': result})
    result, writes, _ = invoke('lookup', OBJECT, modes[0], count=0)
    if result != 0xff or writes:
        raise ValueError('Empty mode list must fail closed.')

    pair_cases = 0
    pair_domain = sorted(set(modes) | set(PAIRS) | {0, 1, 0xffffffff})
    for flag in (0, 1, 2, 0xffffffff):
        for mode in pair_domain:
            result, writes, _ = invoke('paired_mode', flag, mode)
            if result != paired_mode(flag, mode) or writes:
                raise ValueError('Original mode conversion differs from the reviewed model.')
            pair_cases += 1

    stage_results = []
    for index, (mode, column) in enumerate(zip(modes, columns)):
        # Reset only the in-memory descriptors so cross-case state cannot hide a failure.
        for target in target_set:
            machine.mem_write(target, image_slice(data, target, 1))
        _, writes, count = invoke('stage_column', 0, index)
        expected = [(target, row[4+column]) for target, row in zip(targets, rows)]
        if writes != expected:
            raise ValueError('Original staged write order or values differ from the table.')
        final = dict(expected)
        if any(machine.mem_read(address, 1)[0] != value for address, value in final.items()):
            raise ValueError('Emulator staged readback differs.')
        stage_results.append({'mode': hex(mode), 'index': index, 'column': column,
                              'writes': len(writes), 'instructions': count})
    return dict(schema='a7c2-isolated-selector-emulation/1', cp_sha256=CP_SHA,
        original_instructions_executed_in_emulator=True, synthetic_object_state=True,
        helper_stubs=[], hardware_mmio_mapped=False, camera_io=False,
        original_firmware_files_written=False, emulated_descriptor_bytes_written=True,
        full_firmware_booted=False, runtime_camera_state_reproduced=False,
        movie_path_verified=False, recording_verified=False, installable=False,
        leaf_windows=[{'name':name, 'start':hex(start), 'end_exclusive':hex(end),
            'sha256':hashlib.sha256(image_slice(data,start,end-start)).hexdigest()}
            for name,(start,end) in LEAVES.items()],
        lookup_cases=len(lookup_results)+1, lookup_results=lookup_results,
        empty_lookup_returns=255, pair_cases=pair_cases,
        flag_semantics='converter translates only when flag == 1; meaning is not yet named',
        stage_cases=len(stage_results), stage_results=stage_results)
