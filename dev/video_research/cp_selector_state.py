"""Original runtime-mode descriptor copy and selector-class lookup, separately.

No scheduler, hardware state, operating-mode name or physical readout is invented.
The runtime-selected mode and conditional refresh/override remain unresolved.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span

DESCRIPTORS=0xe797a8
JUMP_TABLE=0x4c0358
SNAPSHOT=0x172fe50


def inspect(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    targets=[JUMP_TABLE+v*2 for v in struct.unpack('<29H',cp_span(cp,JUMP_TABLE,58))]
    rows=[]
    for index in (0,6,7,9):
        raw=cp_span(cp,DESCRIPTORS+12*index,12);word=struct.unpack_from('<I',raw)[0]
        branch_class=(word>>17)&31
        rows.append(dict(index=index,record_va=hex(DESCRIPTORS+12*index),record_sha256=hashlib.sha256(raw).hexdigest(),
            branch_class=branch_class,selector_branch=hex(targets[branch_class]) if branch_class<29 else '0x4c04a0'))
    return dict(schema='a7c2-cp-selector-state-static/1',cp_sha256=CP_SHA,
        initialized_instance='0x173efe8',snapshot_base=hex(SNAPSHOT),
        instance_pointer_0c=dict(value=hex(SNAPSHOT+0xe18),derivation='constructor 0xb2ebe0 adds 0xe18; 0xb2ebe4 stores instance +0xc'),
        selector_word=dict(object_offset='0xb98',snapshot_offset='0x19b0',absolute=hex(SNAPSHOT+0x19b0),
            mode_source='snapshot u16 +4 at 0x4d7c64',descriptor_copy_call='0x4d7c70',helper='0x4ba624',
            table=hex(DESCRIPTORS),stride=12,index='input low byte; input bits 5..7 must be below 0x60',
            conditional_override='0x4d7c98..0x4d7cd4 may replace descriptor with input 0x107 (index 7), then clear flag masks'),
        selector_extract=dict(at='0x4c0346',bits='17..21',jump_table=hex(JUMP_TABLE),entries=29),
        example_rows=rows,
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((0xb2ebce,0xb2ebe6),(0x4d7c64,0x4d7c74),(0x4d7c98,0x4d7cd8),
                          (0x4ba624,0x4ba65a),(0x4c0328,0x4c0392))],
        runtime_mode_value_verified=False,mode_enum_names_verified=False,refresh_execution_verified=False,
        movie_to_sensor_selection_verified=False,camera_io=False,recording_verified=False,installable=False)


def run_original(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    targets={JUMP_TABLE+v*2 for v in struct.unpack('<29H',cp_span(cp,JUMP_TABLE,58))}|{0x4c04a0}
    cases=[]
    for mode in (0,6,7,9,0x107,0x60):
        uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        for page,flags in ((0x4ba000,u.UC_PROT_READ|u.UC_PROT_EXEC),(DESCRIPTORS&~4095,u.UC_PROT_READ)):
            uc.mem_map(page,4096,flags);uc.mem_write(page,cp_span(cp,page,4096))
        stack,dest,sentinel,sp=0x20000000,0x21000000,0x22000000,0x20000800
        for page in (stack,dest):uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(page,b'\xa5'*4096)
        uc.mem_map(sentinel,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        for reg,value in ((a.UC_ARM_REG_SP,sp),(a.UC_ARM_REG_R0,mode),(a.UC_ARM_REG_R1,dest+16),(a.UC_ARM_REG_LR,sentinel|1)):
            uc.reg_write(reg,value)
        path=[];stopped=[]
        def instruction(em,addr,size,_):
            if addr in (sentinel,0x4ba632):stopped.append(addr);em.emu_stop();return
            if not (0x4ba624<=addr and addr+size<=0x4ba632 or 0x4ba63e<=addr and addr+size<=0x4ba65a):
                raise ValueError('Unreviewed descriptor-copy instruction.')
            path.append((addr,size))
        def memory(em,access,addr,size,value,_):
            ranges=((sp-16,16),(dest+16,12)) if access==u.UC_MEM_WRITE else ((sp-16,16),(DESCRIPTORS+12*(mode&255),12))
            if not any(lo<=addr and addr+size<=lo+n for lo,n in ranges):raise ValueError('Unexpected descriptor-copy memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x4ba625,0,count=100,timeout=1_000_000)
        rejected=(mode&0xe0)>=0x60
        if stopped!=[0x4ba632 if rejected else sentinel]:raise ValueError('Descriptor stop differs.')
        actual=bytes(uc.mem_read(dest,4096));expected=bytearray(b'\xa5'*4096)
        if not rejected:expected[16:28]=cp_span(cp,DESCRIPTORS+12*(mode&255),12)
        if actual!=expected:raise ValueError('Descriptor copy or canary differs.')
        for lo,hi in ((stack,sp-16),(sp,stack+4096)):
            if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Descriptor stack canary differs.')
        report=dict(synthetic_mode=hex(mode),index=mode&255,rejected_before_diagnostics=rejected,
            copy_instruction_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in path)).hexdigest())
        if not rejected:
            # Separate selector entry: all non-descriptor arguments are synthetic.
            word=struct.unpack_from('<I',actual,16)[0];branch_class=(word>>17)&31
            em=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
            em.mem_map(0x4c0000,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);em.mem_write(0x4c0000,cp_span(cp,0x4c0000,4096))
            instance,obj=0x23000000,0x24000000
            for page in (stack,instance,obj):em.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
            em.mem_write(stack,b'\xa5'*4096);em.mem_write(sp,bytes(32))
            em.mem_write(instance+12,struct.pack('<I',obj));em.mem_write(obj+0xb98,struct.pack('<I',word))
            for page in (instance,obj):em.mem_protect(page,4096,u.UC_PROT_READ)
            em.reg_write(a.UC_ARM_REG_SP,sp);em.reg_write(a.UC_ARM_REG_R0,instance)
            selected=[];spath=[]
            def sinstruction(vm,addr,size,_):
                if addr in targets:selected.append(addr);vm.emu_stop();return
                if not (0x4c0328<=addr and addr+size<=0x4c0358):raise ValueError('Unreviewed selector entry instruction.')
                spath.append((addr,size))
            def smemory(vm,access,addr,size,value,_):
                ranges=((sp-56,56),) if access==u.UC_MEM_WRITE else ((sp+4,4),(sp+16,8),(instance+12,4),(obj+0xb98,4),(JUMP_TABLE,58))
                if not any(lo<=addr and addr+size<=lo+n for lo,n in ranges):raise ValueError('Unexpected selector entry memory access.')
            em.hook_add(u.UC_HOOK_CODE,sinstruction);em.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,smemory)
            em.emu_start(0x4c0329,0,count=100,timeout=1_000_000)
            target=JUMP_TABLE+struct.unpack('<H',cp_span(cp,JUMP_TABLE+branch_class*2,2))[0]*2 if branch_class<29 else 0x4c04a0
            if selected!=[target]:raise ValueError('Selector branch differs.')
            if em.reg_read(a.UC_ARM_REG_SP)!=sp-56:raise ValueError('Selector stack differs.')
            for lo,hi in ((stack,sp-56),(sp+32,stack+4096)):
                if bytes(em.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Selector stack canary differs.')
            report.update(branch_class=branch_class,selector_stop=hex(target),
                selector_instruction_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in spath)).hexdigest())
        cases.append(report)
    return dict(schema='a7c2-cp-selector-state-fragments/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_inputs=True,fragments_executed_separately=True,unknown_helpers_executed=0,
        selector_branch_body_executed=False,runtime_mode_value_verified=False,
        camera_io=False,recording_verified=False,installable=False)
