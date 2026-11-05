"""Bounded snapshot-to-selector field projection using original CP instructions.

The caller's refresh, dirty-state and mode gates are not bypassed in a real camera:
this is a separately executed fragment with explicitly synthetic snapshot inputs.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span,pc_table


def inspect(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    table=pc_table(cp,0x4d7ef2,9)
    choices=[]
    for index in (6,7,9,25):
        word=struct.unpack('<I',cp_span(cp,0xe797a8+12*index,4))[0]
        selector=(word>>4)&15
        choices.append(dict(descriptor_index=index,projection_selector=selector,
            table_target=table['entries'][selector]['target']))
    return dict(schema='a7c2-cp-selector-fields-static/1',cp_sha256=CP_SHA,
        snapshot_base='0x172fe50',selector_object_offset='0xe18',
        instance_root='0xb2ebd2 stores root into instance +0; +0xc stores root+0xe18',
        snapshot_argument_origin='0x4d7e9e reads instance +0 into r1; fp is snapshot root',
        mappings=[dict(source_snapshot_offset=hex(src),destination_snapshot_offset=hex(dst),
            selector_object_offset=hex(dst-0xe18),load=hex(ld),store=hex(st))
            for src,dst,ld,st in ((0x38,0x11fc,0x4d7f08,0x4d7f0e),
                (0x28,0x11d8,0x4d7f16,0x4d7f18),(0x34,0x11e0,0x4d7f1c,0x4d7f22))],
        movie_format_origin='0x3543be writes source object +0x28 from message +8; snapshot refresh is a distinct unresolved edge',
        selector_consumer='0x4c03ae reads object +0x3c0; 0x4c03b2 reads +0x3e4',
        descriptor_examples=choices,projection_table=table,
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((0xb2ebce,0xb2ebe6),(0x4d7e9e,0x4d7f26),(0x4c0392,0x4c03c6))],
        source_38_semantics_verified=False,precondition_gates_executed=False,
        continuous_setting_to_selector_execution_verified=False,camera_io=False,installable=False)


def run_original(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for index in (6,7,9,25):
        em=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        em.mem_map(0x4d7000,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        em.mem_write(0x4d7000,cp_span(cp,0x4d7000,4096))
        root=0x21000000
        em.mem_map(root,8192,u.UC_PROT_READ|u.UC_PROT_WRITE)
        initial=bytearray(b'\xa5'*8192)
        for off,value in ((0x28,3),(0x34,0x1234),(0x38,0x5678)):
            struct.pack_into('<I',initial,off,value)
        initial[0x19b0:0x19b4]=cp_span(cp,0xe797a8+12*index,4)
        em.mem_write(root,bytes(initial))
        for reg,value in ((a.UC_ARM_REG_R0,root+0xe18),(a.UC_ARM_REG_R1,root),(a.UC_ARM_REG_R11,root)):
            em.reg_write(reg,value)
        trace=[];stopped=[]
        def instruction(vm,addr,size,_):
            if addr==0x4d7f26:stopped.append(addr);vm.emu_stop();return
            if not (0x4d7ee4<=addr and addr+size<=0x4d7ef6 or 0x4d7f08<=addr and addr+size<=0x4d7f26):
                raise ValueError('Unreviewed snapshot projection instruction.')
            trace.append((addr,size))
        def memory(vm,access,addr,size,value,_):
            allowed={(root+off,4) for off in ((0x11d8,0x11e0,0x11fc) if access==u.UC_MEM_WRITE else (0x19b0,0x28,0x34,0x38))}
            table=access==u.UC_MEM_READ and size==2 and 0x4d7ef6<=addr<0x4d7f08
            if (addr,size) not in allowed and not table:raise ValueError('Unexpected projection memory access.')
        em.hook_add(u.UC_HOOK_CODE,instruction);em.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        em.emu_start(0x4d7ee5,0,count=100,timeout=1_000_000)
        expected=bytearray(initial)
        for src,dst in ((0x28,0x11d8),(0x34,0x11e0),(0x38,0x11fc)):expected[dst:dst+4]=initial[src:src+4]
        if stopped!=[0x4d7f26] or bytes(em.mem_read(root,8192))!=expected:raise ValueError('Projection or memory canary differs.')
        cases.append(dict(descriptor_index=index,format_to_selector_3c0=3,
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in trace)).hexdigest()))
    return dict(schema='a7c2-cp-selector-fields-fragment/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_snapshot_fields={'0x28':3,'0x34':0x1234,'0x38':0x5678},
        original_descriptor_and_branch_data=True,precondition_gates_executed=False,
        unknown_helpers_executed=0,continuous_setting_to_selector_execution_verified=False,
        camera_io=False,installable=False)
