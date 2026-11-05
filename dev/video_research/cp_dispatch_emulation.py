"""Execute original CP table lookup up to, but not through, indirect dispatch.

The caller and transport are not emulated. Routing state and message are synthetic.
Only the state-zero check callback and its constant getter may execute; no
unknown logging, main-handler or completion helpers are executed.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE, CP_SHA, check_image, cp_span

START, STOP = 0x35cf70, 0x35d07a
TABLE, TABLE_SIZE = 0x10fab8c, 350 * 20
INDEX, INDEX_SIZE = 0xd939f0, 0x178 * 8
GLOBAL, TRACE = 0x186fbf8, 0x1a533a4


def run_original(cp: bytes) -> dict:
    check_image(cp, CP_SIZE, CP_SHA, 'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases = []
    for routing in (0, 1, 0x90030001, 0x80020002):
        stop = STOP
        uc = u.Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB)
        for start, length, flags in ((START & ~4095, 8192, u.UC_PROT_READ | u.UC_PROT_EXEC),
                                     (TABLE, TABLE_SIZE, u.UC_PROT_READ | u.UC_PROT_WRITE),
                                     (0x362000,4096,u.UC_PROT_READ | u.UC_PROT_EXEC),
                                     (0x8db000,4096,u.UC_PROT_READ | u.UC_PROT_EXEC),
                                     (INDEX, INDEX_SIZE, u.UC_PROT_READ)):
            page, end = start & ~4095, (start + length + 4095) & ~4095
            uc.mem_map(page, end-page, flags)
            uc.mem_write(page, cp_span(cp, page, end-page))
        stack, request = 0x20000000, 0x21000000
        for addr in (stack, request, GLOBAL & ~4095, TRACE & ~4095):
            uc.mem_map(addr, 4096, u.UC_PROT_READ | u.UC_PROT_WRITE)
        uc.mem_write(stack, b'\xa5' * 4096)
        uc.mem_write(request, struct.pack('<BBHII', 5, 0, 0x40a3, 0x12345678, 1))
        uc.mem_write(TRACE + 0x32, b'\0')
        for addr in (request, TRACE & ~4095):
            uc.mem_protect(addr, 4096, u.UC_PROT_READ)
        sp = stack + 0x800
        uc.reg_write(a.UC_ARM_REG_SP, sp)
        uc.reg_write(a.UC_ARM_REG_R0, request)
        uc.reg_write(a.UC_ARM_REG_R1, routing)
        stopped, count, check_entries = [], [0], []
        def instruction(em, address, size, unused):
            count[0] += 1
            if address == 0x3626b8:
                check_entries.append(em.reg_read(a.UC_ARM_REG_R1))
            if address == stop:
                stopped.append(address)
                em.emu_stop()
                return
            # Only the reviewed lookup path, not error/log/check-handler paths.
            allowed = ((START, 0x35cfca), (0x35d040, 0x35d054),
                       (0x35d05e, STOP), (0x3626b8,0x3626ce),
                       (0x362712,0x362718), (0x8db1b8,0x8db1c2))
            if not any(lo <= address and address + size <= hi for lo, hi in allowed):
                raise ValueError('Unreviewed dispatcher instruction.')
        def memory(em, access, address, size, value, unused):
            if access == u.UC_MEM_WRITE:
                allowed = sp-72 <= address <= sp-size or (address in (GLOBAL,0x10fb778) and size == 4)
            else:
                allowed = any(lo <= address and address+size <= lo+n for lo, n in
                    ((sp-72, 72), (request, 12), (TABLE, TABLE_SIZE),
                     (INDEX, INDEX_SIZE), (TRACE+0x32, 1), (GLOBAL, 4)))
            if not allowed:
                raise ValueError('Unexpected dispatcher memory access.')
        uc.hook_add(u.UC_HOOK_CODE, instruction)
        uc.hook_add(u.UC_HOOK_MEM_READ | u.UC_HOOK_MEM_WRITE, memory)
        uc.emu_start(START | 1, 0, timeout=1_000_000, count=3000)
        if check_entries != ([0] if routing == 0x80020002 else []):
            raise ValueError('Unexpected check callback state/path.')
        if struct.unpack('<I',bytes(uc.mem_read(0x10fb778,4)))[0] != 0:
            raise ValueError('Unexpected mutable check-state word.')
        if stopped != [stop]:
            raise ValueError('Dispatcher did not reach indirect call.')
        target_reg = a.UC_ARM_REG_R1
        target = 0x358755
        if (uc.reg_read(a.UC_ARM_REG_R0), uc.reg_read(target_reg),
            uc.reg_read(a.UC_ARM_REG_R5), uc.reg_read(a.UC_ARM_REG_SP)) != (
                request, target, 0x10fb76c+8, sp-48):
            raise ValueError('Unexpected dispatch arguments/table row/stack.')
        if bytes(uc.mem_read(stack, sp-72-stack)) != b'\xa5' * (sp-72-stack):
            raise ValueError('Lower stack canary changed.')
        if bytes(uc.mem_read(sp, 4096-(sp-stack))) != b'\xa5' * (4096-(sp-stack)):
            raise ValueError('Upper stack canary changed.')
        cases.append(dict(synthetic_second_argument=hex(routing), message_id='0x40a3',
            row_va='0x10fb76c', next_indirect_target=hex(target),
            call_kind='main_handler',
            state_zero_check_executed=bool(check_entries),
            check_state_word=0,
            stopped_before=hex(stop), instructions=count[0]-1))
    return dict(schema='a7c2-cp-dispatch-prefix/1', cp_sha256=CP_SHA,
        reviewed_ranges=[dict(start=hex(start),size=size,
            sha256=hashlib.sha256(cp_span(cp,start,size)).hexdigest())
            for start,size in ((START, STOP-START), (TABLE,TABLE_SIZE),(INDEX,INDEX_SIZE),(0x3626b8,0x60),(0x8db1b8,10))],
        cases=cases, case_count=len(cases), synthetic_context=True,
        second_argument_semantics_verified=False,state_one_check_executed=False,
        mutable_check_state_lifecycle=dict(
            raw_table_state=0,per_row_offset=12,
            conditional_bulk_set_va='0x353e46',bulk_row_count=350,
            value_assignment_va='0x353e20',assigned_value=1,
            condition='bit 0 of byte at 0x1a533a4 + 0xe0 is set',
            reviewed_prefix_sha256=hashlib.sha256(cp_span(cp,0x353e1a,0x42)).hexdigest(),
            calls_between_assignment_and_loop_executed=False,
            per_message_clear_va='0x35d072',runtime_flag_value_verified=False),
        handler_executed=False, transport_verified=False, movie_path_verified=False,
        recording_verified=False, camera_io=False, firmware_file_written=False, installable=False)


def run_state_lifecycle_original(cp: bytes) -> dict:
    """Original conditional bulk loop; r4=1 is a declared entry precondition.

    Earlier calls between the assignment and this fragment are not stubbed or
    executed. This verifies the loop, not that the runtime condition is enabled.
    """
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    start,stop=0x353e36,0x353e5c
    cases=[]
    for flag in (0,1,2):
        uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        uc.mem_map(start & ~4095,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        uc.mem_write(start & ~4095,cp_span(cp,start & ~4095,4096))
        lo,hi=TABLE & ~4095,(TABLE+TABLE_SIZE+4095)&~4095
        uc.mem_map(lo,hi-lo,u.UC_PROT_READ|u.UC_PROT_WRITE)
        original=cp_span(cp,lo,hi-lo)
        uc.mem_write(lo,original)
        uc.mem_map(TRACE & ~4095,4096,u.UC_PROT_READ)
        uc.mem_write(TRACE+0xe0,bytes([flag]))
        uc.reg_write(a.UC_ARM_REG_R4,1)
        stopped=[];writes=[]
        def instruction(em,address,size,unused):
            if address==stop:stopped.append(address);em.emu_stop();return
            if not start<=address<stop:raise ValueError('Unreviewed lifecycle instruction.')
        def memory(em,access,address,size,value,unused):
            if access==u.UC_MEM_READ:
                if (address,size)!=(TRACE+0xe0,1):raise ValueError('Unexpected lifecycle read.')
            else:
                if not (TABLE+12<=address<TABLE+TABLE_SIZE and
                        (address-TABLE)%20==12 and size==4 and value==1):
                    raise ValueError('Unexpected lifecycle write.')
                writes.append(address)
        uc.hook_add(u.UC_HOOK_CODE,instruction)
        uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(start|1,0,count=2000,timeout=1_000_000)
        expected=bytearray(original)
        addresses=list(range(TABLE+12,TABLE+TABLE_SIZE,20)) if flag&1 else []
        for address in addresses:struct.pack_into('<I',expected,address-lo,1)
        if stopped!=[stop] or writes!=addresses or bytes(uc.mem_read(lo,hi-lo))!=expected:
            raise ValueError('Conditional table lifecycle mismatch.')
        cases.append(dict(synthetic_flag_byte=flag,entry_r4_precondition=1,
                          changed_state_words=len(writes),table_other_bytes_preserved=True))
    return dict(schema='a7c2-cp-state-lifecycle/1',cp_sha256=CP_SHA,cases=cases,
        prefix_sha256=hashlib.sha256(cp_span(cp,start,stop-start)).hexdigest(),
        earlier_calls_executed=False,runtime_flag_value_verified=False,
        camera_io=False,firmware_file_written=False,movie_path_verified=False,
        recording_verified=False,installable=False)
