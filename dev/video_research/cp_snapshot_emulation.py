"""Verify one original Thumb -> ARM copy -> Thumb initialization snapshot.

This is not live synchronization: stop before later initialization helpers. The
source bytes are synthetic, and constructor reachability/timing is not assumed.
"""
from __future__ import annotations
import hashlib
from request_trace import CP_SIZE, CP_SHA, check_image, cp_span

START, STOP = 0xb2e140, 0xb2e168
GETTER = (0x8dad4a, 0x8dad54)
COPY = (0x61e60c, 0x61e6c4)
SOURCE, DESTINATION, LENGTH = 0x165a720, 0x172fe50, 0xd64


def run_original(cp: bytes) -> dict:
    check_image(cp, CP_SIZE, CP_SHA, 'CP')
    import unicorn as u
    from unicorn import arm_const as a
    uc = u.Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB)
    for lo, hi in ((START, STOP), GETTER, COPY):
        page = lo & ~4095
        uc.mem_map(page, 4096, u.UC_PROT_READ | u.UC_PROT_EXEC)
        uc.mem_write(page, cp_span(cp,page,4096))
    for addr in (SOURCE, DESTINATION):
        lo, hi = addr & ~4095, (addr+LENGTH+4095) & ~4095
        uc.mem_map(lo,hi-lo,u.UC_PROT_READ | u.UC_PROT_WRITE)
        uc.mem_write(lo,b'\xa5'*(hi-lo))
    expected = bytes((i*37+11) & 255 for i in range(LENGTH))
    uc.mem_write(SOURCE,expected)
    uc.mem_protect(SOURCE & ~4095,8192,u.UC_PROT_READ)
    stack, sp = 0x20000000, 0x20000800
    uc.mem_map(stack,4096,u.UC_PROT_READ | u.UC_PROT_WRITE)
    uc.mem_write(stack,b'\xa5'*4096)
    uc.reg_write(a.UC_ARM_REG_SP,sp)
    stopped, count, modes = [], [0], set()
    def instruction(em,address,size,unused):
        count[0] += 1
        if address == STOP:
            stopped.append(address)
            em.emu_stop()
            return
        if not any(lo <= address and address+size <= hi for lo,hi in
                   ((START,STOP), GETTER, COPY)):
            raise ValueError('Unreviewed snapshot instruction.')
        thumb = bool(em.reg_read(a.UC_ARM_REG_CPSR) & 0x20)
        if thumb == (COPY[0] <= address < COPY[1]):
            raise ValueError('Unexpected instruction-set state.')
        modes.add('Thumb' if thumb else 'ARM')
    def memory(em,access,address,size,value,unused):
        if access == u.UC_MEM_WRITE:
            allowed = ((sp-92 <= address <= sp-size) or
                       DESTINATION <= address <= DESTINATION+LENGTH-size)
        else:
            allowed = ((sp-92 <= address <= sp-size) or
                       SOURCE <= address <= SOURCE+LENGTH-size)
        if not allowed:
            raise ValueError('Unexpected snapshot memory access.')
    uc.hook_add(u.UC_HOOK_CODE,instruction)
    uc.hook_add(u.UC_HOOK_MEM_READ | u.UC_HOOK_MEM_WRITE,memory)
    uc.emu_start(START | 1,0,count=10000,timeout=1_000_000)
    if stopped != [STOP] or modes != {'Thumb','ARM'}:
        raise ValueError('Snapshot did not return through both instruction sets.')
    if uc.reg_read(a.UC_ARM_REG_SP) != sp-80:
        raise ValueError('Unexpected snapshot stack adjustment.')
    if bytes(uc.mem_read(DESTINATION,LENGTH)) != expected:
        raise ValueError('Snapshot copy differs.')
    for lo,hi in ((stack,sp-92),(sp,stack+4096),
                  (DESTINATION & ~4095,DESTINATION),
                  (DESTINATION+LENGTH,(DESTINATION+LENGTH+4095)&~4095)):
        if bytes(uc.mem_read(lo,hi-lo)) != b'\xa5'*(hi-lo):
            raise ValueError('Snapshot boundary canary changed.')
    return dict(schema='a7c2-cp-initialization-snapshot/1',cp_sha256=CP_SHA,
        source=hex(SOURCE),destination=hex(DESTINATION),length=LENGTH,
        copied_offsets=['0x2a0','0x2a4'],instructions=count[0]-1,
        stopped_before=hex(STOP),synthetic_source=True,
        reviewed_ranges=[dict(start=hex(lo),end=hex(hi),
            sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((START,STOP),GETTER,COPY)],
        conditional_refresh_static_candidate=dict(
            callsite='0x4d7a68',callee='0x8dad54',copy_callsite='0x8dad74',
            prior_helper='0x5e25a0',required_helper_result=0,
            source=hex(SOURCE),destination=hex(DESTINATION),length=LENGTH,
            prefix_sha256=hashlib.sha256(cp_span(cp,0x8dad54,0x24)).hexdigest(),
            caller_prefix_sha256=hashlib.sha256(cp_span(cp,0x4d79e2,0x8a)).hexdigest(),
            helper_executed=False,refresh_executed=False,
            helper_runtime_requirements=['CPSR interrupt state','CP15 core identifier',
                'per-core pointer table at 0x1b30708','runtime object field +0x40'],
            helper_prefix_sha256=hashlib.sha256(cp_span(cp,0x5e25a0,0x64)).hexdigest(),
            event_order_or_movie_reachability_verified=False),
        initialization_snapshot_only=True,live_synchronization_verified=False,
        subsequent_constructor_executed=False,unknown_helpers_executed=0,
        movie_path_verified=False,recording_verified=False,camera_io=False,
        firmware_file_written=False,installable=False)
