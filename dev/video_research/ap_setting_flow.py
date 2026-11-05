"""Pinned, read-only AP state-write and request-input evidence.

These static edges are not one continuous execution. Queue producers, lock helpers,
notification ordering, callback scheduling and camera readout remain unverified.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE, AP_SHA, Elf64, check_image, span
from ap_xrefs import direct_calls, relative_relocations

STATE = 0x7e59d18
JUMP_TABLE = 0x4b8df18
JUMP_BASE = 0x2db5cf8
COMMAND = 0x9c


def jump_target(elf: Elf64, index: int) -> int:
    if type(index) is not int or not 0 <= index <= 0x262:
        raise ValueError('Command index exceeds original dispatcher bound.')
    slot = JUMP_TABLE + index * 4
    delta = struct.unpack('<i', span(elf.data, elf.file_offset(slot, 4), 4))[0]
    target = JUMP_BASE + delta * 4
    elf.file_offset(target, 4)
    return target


def inspect(ap: bytes) -> dict:
    check_image(ap, AP_SIZE, AP_SHA, 'AP')
    elf = Elf64(ap)
    if jump_target(elf, COMMAND) != 0x2dd4e24:
        raise ValueError('Original command branch differs.')
    spans = (
        ('notify-command-producer', 0x353367c, 0x35336a8),
        ('notify-value-converter', 0x3521730, 0x35217f8),
        ('queue-push-prefix', 0x2db0570, 0x2db05f8),
        ('queue-pop-and-dispatch', 0x2db5c98, 0x2db5cf8),
        ('command-value-to-wrapper', 0x2dd4e24, 0x2dd4e44),
        ('wrapper', 0x2631510, 0x26315bc),
        ('state-writer', 0x26313e8, 0x2631510),
        ('state-getter', 0x285d6d0, 0x285d6e4),
        ('sequence-to-builder-wrapper', 0x344c80c, 0x344c878),
        ('builder-wrapper', 0x34ce4c8, 0x34ce504),
    )
    evidence = []
    for label, lo, hi in spans:
        offset = elf.file_offset(lo, hi-lo)
        evidence.append(dict(label=label, va=hex(lo), end_exclusive=hex(hi),
            file_offset=hex(offset), sha256=hashlib.sha256(span(ap,offset,hi-lo)).hexdigest()))
    # The queue entry contains command at +0 and candidate setting at +4.
    # This is a dispatcher command, NOT a proven UI/menu identifier.
    return dict(schema='a7c2-ap-setting-static-flow/1', ap_sha256=AP_SHA,
        state_address=hex(STATE), getter='0x285d6d0',
        dispatcher=dict(index=hex(COMMAND), table=hex(JUMP_TABLE),
            slot=hex(JUMP_TABLE+COMMAND*4), relative_base=hex(JUMP_BASE),
            target=hex(jump_target(elf,COMMAND)), command_offset=0, value_offset=4,
            branch_range_sha256=hashlib.sha256(span(ap,elf.file_offset(JUMP_TABLE+COMMAND*4,4),4)).hexdigest(),
            queue_producer_verified=True, ui_identifier_verified=False),
        notification=dict(message_id='0x2054',value_offset=8,producer='0x353367c',
            converter='0x3521730',command_id='0x9c',queue_push='0x2db0570',
            diagnostic_va='0x4c88fa0',
            diagnostic='convert_imager_frame_size_info_notify',
            source_is_user_setting_verified=False),
        edges=[
            dict(source='notification +8 byte', instruction='0x3533694', destination='command +4 word via converter', call='0x3533698'),
            dict(source='queue-entry +4', instruction='0x2dd4e2c', destination='wrapper w1', call='0x2dd4e38'),
            dict(source='wrapper w1', instruction='0x263152c', destination='stack +0x3c; reload w1 at 0x263157c', call='0x2631584'),
            dict(source='writer w1', instruction='0x2631404', destination='w19; original state pointer from getter', store='0x2631470'),
            dict(source='getter state', instruction='0x344c840', destination='sequence instance +0x18', store='0x344c848'),
            dict(source='sequence instance +0x18', instruction='0x344c860', destination='builder input +8', store='0x344c864', call='0x344c874'),
        ],
        call_references=direct_calls(elf,{0x2631510,0x26313e8,0x34ce4c8}),
        callback_relocations=relative_relocations(elf,{0x344c80c}),
        reviewed_ranges=evidence, synthetic_inputs=False, instructions_executed=False,
        unresolved=['actual UI setting identity: this discovered producer is an imaging-info notification',
            'lock/notification helper behavior and intervening memory side effects',
            'sequence callback scheduling after a state update',
            'live FULL/APSC interpretation and physical sensor readout'],
        continuous_execution_verified=False, movie_path_verified=False,
        recording_verified=False, camera_io=False, installable=False)


def run_original(ap: bytes) -> dict:
    """Original notification branch and converter, separate; no helper stubs."""
    check_image(ap, AP_SIZE, AP_SHA, 'AP')
    elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    cases=[]
    # Stop BEFORE allocation on neighboring paths, before the notify producer,
    # before invalid-value diagnostics, or at a synthetic return sentinel.
    stages=(('message_dispatch',0x3531660,(0x2053,0x2054,0x2055,0x2056)),
            ('notification_value',0x3521730,(0,1,2,255)))
    for phase,start,values in stages:
        for value in values:
            uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
            if phase=='message_dispatch':
                lo,n=0x3531000,0x5000
                stops={0x3534b30,0x353367c,0x35350f4,0x3531ffc}
            else:
                lo,n=0x3521000,0x1000
                stops={0x3521740,0x10001000}
            uc.mem_map(lo,n,u.UC_PROT_READ|u.UC_PROT_EXEC)
            uc.mem_write(lo,span(ap,elf.file_offset(lo,n),n))
            inp=0x10000000
            uc.mem_map(inp,8192,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.mem_write(inp,b'\xa5'*8192)
            if phase=='message_dispatch':
                uc.mem_write(inp+2,struct.pack('<H',value))
                uc.reg_write(a.UC_ARM64_REG_X19,inp)
            else:
                uc.reg_write(a.UC_ARM64_REG_W0,value)
                uc.reg_write(a.UC_ARM64_REG_X1,inp)
                uc.reg_write(a.UC_ARM64_REG_LR,inp+4096)
                uc.mem_protect(inp+4096,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            path=[];stopped=[]
            def instruction(em,address,size,_):
                if address in stops:stopped.append(address);em.emu_stop();return
                if size!=4 or not lo<=address<lo+n:raise ValueError('Unreviewed notification instruction.')
                word=int.from_bytes(em.mem_read(address,4),'little')
                if word&0xfc000000==0x94000000:raise ValueError('No notification helper execution allowed.')
                path.append(address)
            def memory(em,access,address,size,value_written,_):
                expected=(inp+2,2,u.UC_MEM_READ) if phase=='message_dispatch' else (inp+4,4,u.UC_MEM_WRITE)
                if (address,size,access)!=expected:raise ValueError('Unexpected notification memory access.')
            uc.hook_add(u.UC_HOOK_CODE,instruction)
            uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(start,0,count=150,timeout=1_000_000)
            expected_stop=({0x2053:0x3534b30,0x2054:0x353367c,0x2055:0x35350f4,0x2056:0x3531ffc}[value]
                if phase=='message_dispatch' else inp+4096 if value in (0,1) else 0x3521740)
            if stopped!=[expected_stop]:raise ValueError('Unexpected notification stop.')
            actual=bytes(uc.mem_read(inp,4096));expected=bytearray(b'\xa5'*4096)
            if phase=='message_dispatch':struct.pack_into('<H',expected,2,value)
            elif value in (0,1):struct.pack_into('<I',expected,4,value)
            if actual!=expected:raise ValueError('Notification value/canary mismatch.')
            cases.append(dict(phase=phase,synthetic_value=hex(value),stopped_before=hex(expected_stop),
                instruction_addresses=[hex(x) for x in path],
                instruction_stream_sha256=hashlib.sha256(b''.join(
                    span(ap,elf.file_offset(x,4),4) for x in path)).hexdigest(),
                command_value=value if phase=='notification_value' and value in (0,1) else None))
    return dict(schema='a7c2-ap-notification-fragments/1',ap_sha256=AP_SHA,cases=cases,
        synthetic_inputs=True,fragments_executed_separately=True,helper_calls_executed=0,
        queue_operation_executed=False,user_setting_provenance_verified=False,
        camera_io=False,recording_verified=False,installable=False)
