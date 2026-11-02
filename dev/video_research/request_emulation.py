"""Execute a reviewed original CP availability/selector chain in isolated RAM.

Receiver identity and exclusion state are synthetic, not camera observations.
Policy == 1 deliberately stops at the unreviewed extra helper; no success stubs.
"""
from __future__ import annotations

import hashlib
import struct

from request_trace import BASE, CP_SIZE, CP_SHA, check_image, cp_span

MODE_TABLE, VTABLE = 0xDE99D4, 0xDE98A0
HANDLE, EXCLUSION = 0x018AEB8C, 0x012110D0
RECEIVER, TABLE_OBJECT = 0x20000000, 0x20001000
STACK, STOP = 0x21000000, 0x30000000
INITIAL_SP = STACK + 0x3000
CODE = {
    'instance': (0x989D4A, 0x989D54),
    'dispatch': (0x989E8A, 0x989E94),
    'availability': (0x98D284, 0x98D2B6),
    'lookup': (0x98DF72, 0x98DF94),
    'pair': (0xB2A04C, 0xB2A17C),
    'selector': (0xB2A87C, 0xB2A8CC),
    'predicate': (0xB2A8CC, 0xB2A906),
}
EXTRA_HELPER = 0xB0B196


def uint(value: int, bits: int = 32) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError('Unsigned integer outside reviewed width.')
    return value


def available(modes: tuple[int, ...], mode: int, excluded: int) -> int:
    uint(mode)
    uint(excluded, 16)
    if len(modes) > 255:
        raise ValueError('Mode count exceeds the lookup index width.')
    for value in modes:
        uint(value)
    return int(mode in modes and mode != excluded)


def select_mode(modes: tuple[int, ...], flag: int, policy: int, excluded: int) -> int:
    """Model only the no-extra-helper path. Never invent policy-1 outcomes."""
    uint(flag)
    uint(policy)
    uint(excluded, 16)
    if policy == 1:
        raise ValueError('Policy 1 requires a separate, unverified query chain.')
    first, second = (0x5004, 0x5021) if flag else (0x5002, 0x5020)
    result = 0x5002 if available(modes, first, excluded) else (
        0x5020 if available(modes, second, excluded) else 0x5000)
    if flag == 1:
        result = {0x5002: 0x5004, 0x5020: 0x5021, 0x5000: 0x5001}[result]
    return result


def contains(ranges: tuple[tuple[int, int], ...], address: int, size: int) -> bool:
    return (type(address) is int and type(size) is int and size > 0
            and any(start <= address and address + size <= end for start, end in ranges))


def run_original(data: bytes) -> dict:
    check_image(data, CP_SIZE, CP_SHA, 'CP')
    # Optional dependencies must not be imported before identity verification.
    import unicorn as u
    from unicorn import arm_const as a

    modes = struct.unpack('<30I', cp_span(data, MODE_TABLE, 120))
    if len(set(modes)) != 30:
        raise ValueError('Unexpected original mode table.')
    slot = struct.unpack('<I', cp_span(data, VTABLE + 0xD4, 4))[0]
    if slot != CODE['availability'][0] | 1:
        raise ValueError('Original availability slot differs.')
    machine = u.Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB)
    original_pages: dict[int, int] = {}

    def pages(start: int, size: int, rights: int) -> None:
        cp_span(data, start, size)
        for page in range(start & ~4095, (start + size + 4095) & ~4095, 4096):
            original_pages[page] = original_pages.get(page, 0) | rights

    for start, end in CODE.values():
        pages(start, end - start, u.UC_PROT_READ | u.UC_PROT_EXEC)
    # Map the rejection target so the code hook can prove it stops BEFORE execution.
    pages(EXTRA_HELPER, 2, u.UC_PROT_READ | u.UC_PROT_EXEC)
    pages(VTABLE + 0xD4, 4, u.UC_PROT_READ)
    pages(MODE_TABLE, 120, u.UC_PROT_READ)
    for page, rights in original_pages.items():
        if rights & u.UC_PROT_WRITE:
            raise ValueError('Original pages must not be writable.')
        machine.mem_map(page, 4096, rights)
        machine.mem_write(page, cp_span(data, page, 4096))
    for address in (HANDLE, EXCLUSION, RECEIVER, TABLE_OBJECT):
        page = address & ~4095
        if page in original_pages:
            raise ValueError('Synthetic state overlaps original code or tables.')
        machine.mem_map(page, 4096, u.UC_PROT_READ)
    machine.mem_map(STACK, 0x4000, u.UC_PROT_READ | u.UC_PROT_WRITE)
    machine.mem_map(STOP, 4096, u.UC_PROT_READ | u.UC_PROT_EXEC)
    machine.mem_write(HANDLE, struct.pack('<I', RECEIVER))
    machine.mem_write(RECEIVER, struct.pack('<I', VTABLE))
    machine.mem_write(RECEIVER + 0x684, struct.pack('<I', TABLE_OBJECT))
    read_ranges = (
        (HANDLE, HANDLE + 4), (EXCLUSION, EXCLUSION + 2),
        (RECEIVER, RECEIVER + 4), (RECEIVER + 0x684, RECEIVER + 0x688),
        (TABLE_OBJECT + 4, TABLE_OBJECT + 12), (MODE_TABLE, MODE_TABLE + 120),
        (VTABLE + 0xD4, VTABLE + 0xD8), (INITIAL_SP - 0x100, INITIAL_SP),
    )
    stack_range = ((INITIAL_SP - 0x100, INITIAL_SP),)
    state = dict(error=None, stopped_at=None, instructions=0, writes=0, entries=set())

    def fail(reason, address):
        state['error'], state['stopped_at'] = reason, address
        machine.emu_stop()

    def code_hook(uc, address, size, _):
        if not contains(tuple(CODE.values()), address, size):
            fail('outside-reviewed-code', address)
            return
        state['instructions'] += 1
        state['entries'].add(address)

    def read_hook(uc, access, address, size, value, _):
        if not contains(read_ranges, address, size):
            fail('outside-reviewed-read', address)

    def write_hook(uc, access, address, size, value, _):
        if not contains(stack_range, address, size):
            fail('outside-stack-write', address)
        else:
            state['writes'] += 1

    machine.hook_add(u.UC_HOOK_CODE, code_hook)
    machine.hook_add(u.UC_HOOK_MEM_READ, read_hook)
    machine.hook_add(u.UC_HOOK_MEM_WRITE, write_hook)
    registers = [getattr(a, 'UC_ARM_REG_R' + str(i)) for i in range(13)]
    canary = bytes([0xA5]) * 0x4000

    def invoke(name, r0, r1, excluded, count=30, *, rejection=False):
        state.update(error=None, stopped_at=None, instructions=0, writes=0, entries=set())
        machine.mem_write(STACK, canary)
        machine.mem_write(EXCLUSION, struct.pack('<H', excluded))
        machine.mem_write(TABLE_OBJECT + 4, struct.pack('<II', count, MODE_TABLE))
        machine.reg_write(a.UC_ARM_REG_CPSR, 0x30)
        for i, reg in enumerate(registers):
            machine.reg_write(reg, 0xA0000000 + i)
        machine.reg_write(a.UC_ARM_REG_SP, INITIAL_SP)
        machine.reg_write(a.UC_ARM_REG_LR, STOP | 1)
        machine.reg_write(a.UC_ARM_REG_R0, r0)
        machine.reg_write(a.UC_ARM_REG_R1, r1)
        machine.emu_start(CODE[name][0] | 1, STOP, timeout=200000, count=4096)
        if rejection:
            if state['error'] != 'outside-reviewed-code' or state['stopped_at'] != EXTRA_HELPER:
                raise ValueError('Policy-1 negative control did not stop at the extra helper.')
            return None
        if state['error'] or machine.reg_read(a.UC_ARM_REG_PC) != STOP:
            raise ValueError(str(state['error'] or 'Execution did not return within its limits.'))
        if machine.reg_read(a.UC_ARM_REG_SP) != INITIAL_SP:
            raise ValueError('Unbalanced original stack.')
        for i in range(4, 12):
            if machine.reg_read(registers[i]) != 0xA0000000 + i:
                raise ValueError('Callee-saved register was not restored.')
        if machine.mem_read(INITIAL_SP, 32) != bytes([0xA5]) * 32:
            raise ValueError('Stack upper canary changed.')
        return machine.reg_read(a.UC_ARM_REG_R0)

    exclusions = (0, 0x5002, 0x5004, 0x5020, 0x5021, 0xFFFF)
    query_cases = 0
    for excluded in exclusions:
        for mode in (*modes, 0, 1, 0xFFFFFFFF):
            actual = invoke('dispatch', HANDLE, mode, excluded)
            if actual != available(modes, mode, excluded):
                raise ValueError('Original virtual availability differs from reviewed model.')
            if CODE['availability'][0] not in state['entries'] or CODE['lookup'][0] not in state['entries']:
                raise ValueError('Expected original nested calls were not executed.')
            query_cases += 1
    selector_cases = []
    for count in (30, 0):
        active = modes[:count]
        for flag in (0, 1, 2, 0xFFFFFFFF):
            for policy in (0, 2):
                for excluded in exclusions:
                    actual = invoke('selector', flag, policy, excluded, count=count)
                    if actual != select_mode(active, flag, policy, excluded):
                        raise ValueError('Original selector differs from reviewed model.')
                    if not all(CODE[k][0] in state['entries'] for k in ('instance', 'dispatch', 'availability', 'lookup', 'pair', 'predicate')):
                        raise ValueError('Selector did not exercise the full reviewed call chain.')
                    selector_cases.append(dict(flag=flag, policy=policy, excluded=hex(excluded),
                        mode_count=count, result=hex(actual), instructions=state['instructions']))
    invoke('selector', 0, 1, 0, rejection=True)
    return dict(schema='a7c2-request-chain-emulation/1', cp_sha256=CP_SHA,
        original_instructions_executed_in_emulator=True, synthetic_receiver_state=True,
        synthetic_exclusion_state=True, synthetic_empty_table_negative_control=True,
        code_windows=[dict(name=n, start=hex(s), end_exclusive=hex(e),
            sha256=hashlib.sha256(cp_span(data, s, e-s)).hexdigest()) for n,(s,e) in CODE.items()],
        availability_cases=query_cases, selector_cases=len(selector_cases),
        selector_results=selector_cases, policy_1_negative_controls=1,
        policy_1_stopped_before=hex(EXTRA_HELPER), helper_stubs=[],
        writes_allowed='bounded emulator stack only', hardware_mmio_mapped=False,
        camera_io=False, firmware_files_written=False, full_firmware_booted=False,
        runtime_receiver_verified=False, movie_path_verified=False,
        recording_verified=False, installable=False)
