"""Original format-3 selector with a declared original availability graph.

The handle/receiver/table object are synthetic. The vtable slot, mode IDs and
all executed instructions are original; no hardware or helper result is stubbed.
Failure paths stop before diagnostics, not after a fabricated successful call.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span
from request_emulation import MODE_TABLE,VTABLE,HANDLE,EXCLUSION,RECEIVER,TABLE_OBJECT,STACK,STOP,INITIAL_SP,CODE,contains


def inspect(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    modes=struct.unpack('<30I',cp_span(cp,MODE_TABLE,120))
    return dict(schema='a7c2-cp-movie-selector-static/1',cp_sha256=CP_SHA,
        rate_projection=dict(source='snapshot +0x2c',destination='snapshot +0x11cc = selector object +0x3b4',
            instructions='0x4d836e..0x4d8374',condition='descriptor low bits 3; ordinary branch with snapshot +0x3d4 !=1 or projected +0x1210 ==0; rate-3 helper branch and other overrides unresolved'),
        normalized_rate_zero_selector=dict(entry='0x4c0392',branch='0x4c082e',callee='0xb29ab0',
            reason='unsigned (rate - 2) > 4'),
        flag_provenance=dict(source='snapshot +0x2a0 at 0xb2a98e',normalize='0xb2aa5e/0xb2aa6a',
            caller_store='0xb2aa72 stores flag at outgoing stack +4',
            selector_load='0x4c0336 reads entry stack +4 into sl',
            callee_argument='0x4c083e/0x4c0840 passes it as r0',
            semantic_full_apsc_enum_verified=False),
        inventory_frames=[dict(mode=hex(mid),table_index=modes.index(mid),
            width=struct.unpack('<H',cp_span(cp,0xee01d6+modes.index(mid)*0x26+8,2))[0],
            height=struct.unpack('<H',cp_span(cp,0xee01d6+modes.index(mid)*0x26+0x1a,2))[0],
            frame_record_sha256=hashlib.sha256(cp_span(cp,0xee01d6+modes.index(mid)*0x26,0x26)).hexdigest(),
            physical_fov_or_rate_verified=False) for mid in (0x821,0x880,0xb20)],
        format_three_candidates=[dict(mode=hex(x),present_in_original_table=x in modes) for x in (0x821,0x820,0x2820,0xb20)],
        availability=dict(original_vtable=hex(VTABLE),slot='0xd4',handler='0x98d284',lookup='0x98df72',
            declared_table=hex(MODE_TABLE),runtime_object_binding_verified=False),
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((0x4d80d2,0x4d80ee),(0x4d836e,0x4d8382),(0x4c0392,0x4c03a4),
                         (0x4c082e,0x4c0848),(0xb2a980,0xb2a992),(0xb2aa5a,0xb2aa90),(0xb29ab0,0xb29c20))],
        full_frame_capability_verified=False,continuous_execution_verified=False,camera_io=False,installable=False)


def run_original(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    if struct.unpack('<I',cp_span(cp,VTABLE+0xd4,4))[0]!=0x98d285:
        raise ValueError('Original availability slot differs.')
    reviewed=tuple(CODE[k] for k in ('instance','dispatch','availability','lookup'))+((0xb29ab0,0xb29c20),)
    cases=[]
    for flag,raw,excluded in ((0,0,0),(1,0,0),(0,2,0),(1,2,0),(1,0,0x821)):
        em=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        pages=set()
        for lo,hi in (*reviewed,(MODE_TABLE,MODE_TABLE+120),(VTABLE,VTABLE+0xd8)):
            pages.update(range(lo&~4095,(hi+4095)&~4095,4096))
        for page in pages:
            em.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);em.mem_write(page,cp_span(cp,page,4096))
        for addr in (HANDLE,EXCLUSION,RECEIVER,TABLE_OBJECT):em.mem_map(addr&~4095,4096,u.UC_PROT_READ)
        em.mem_map(STACK,0x4000,u.UC_PROT_READ|u.UC_PROT_WRITE);em.mem_write(STACK,b'\xa5'*0x4000)
        em.mem_map(STOP,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        for addr,rawbytes in ((HANDLE,struct.pack('<I',RECEIVER)),(EXCLUSION,struct.pack('<H',excluded)),
            (RECEIVER,struct.pack('<I',VTABLE)),(RECEIVER+0x684,struct.pack('<I',TABLE_OBJECT)),
            (TABLE_OBJECT+4,struct.pack('<II',30,MODE_TABLE))):em.mem_write(addr,rawbytes)
        for reg,value in ((a.UC_ARM_REG_R0,flag),(a.UC_ARM_REG_R1,3),(a.UC_ARM_REG_R2,0),
                          (a.UC_ARM_REG_R3,raw),(a.UC_ARM_REG_SP,INITIAL_SP),(a.UC_ARM_REG_LR,STOP|1)):
            em.reg_write(reg,value)
        trace=[];stopped=[];queries=[]
        def instruction(vm,addr,size,_):
            if addr in (STOP,0xb29bf6):stopped.append(addr);vm.emu_stop();return
            if not contains(reviewed,addr,size):raise ValueError('Unreviewed selector instruction.')
            if addr==0x989e8a:queries.append(vm.reg_read(a.UC_ARM_REG_R1))
            trace.append((addr,size))
        def memory(vm,access,addr,size,value,_):
            ranges=((INITIAL_SP-0x100,INITIAL_SP),)
            if access==u.UC_MEM_READ:ranges+=((HANDLE,HANDLE+4),(EXCLUSION,EXCLUSION+2),
                (RECEIVER,RECEIVER+4),(RECEIVER+0x684,RECEIVER+0x688),
                (TABLE_OBJECT+4,TABLE_OBJECT+12),(MODE_TABLE,MODE_TABLE+120),(VTABLE+0xd4,VTABLE+0xd8))
            if not contains(ranges,addr,size):raise ValueError('Unexpected movie selector memory access.')
        em.hook_add(u.UC_HOOK_CODE,instruction);em.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        em.emu_start(0xb29ab1,0,count=2000,timeout=1_000_000)
        success=flag==1 and excluded!=0x821
        if stopped!=[STOP if success else 0xb29bf6]:raise ValueError('Unexpected selector outcome.')
        result=em.reg_read(a.UC_ARM_REG_R0) if success else None
        if success and (result!=0x821 or em.reg_read(a.UC_ARM_REG_SP)!=INITIAL_SP):raise ValueError('Selector return differs.')
        for lo,hi in ((STACK,INITIAL_SP-0x100),(INITIAL_SP,STACK+0x4000)):
            if bytes(em.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Selector stack canary differs.')
        cases.append(dict(synthetic_flag=flag,synthetic_raw=raw,synthetic_excluded_mode=hex(excluded),
            original_queries=[hex(q) for q in queries],returned_mode=hex(result) if result is not None else None,
            stopped_before_diagnostic=not success,
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in trace)).hexdigest()))
    return dict(schema='a7c2-cp-movie-selector-fragments/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_receiver_graph=True,original_vtable_and_mode_table=True,
        availability_runtime_binding_verified=False,unknown_helpers_stubbed=0,
        diagnostic_or_fallback_after_diagnostic_executed=False,
        continuous_setting_to_sensor_execution_verified=False,camera_io=False,installable=False)


def run_rate_projection(cp: bytes) -> dict:
    """Ordinary conditional projection then independent selector dispatch prefix."""
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    targets={0x4c03a4+2*x for x in struct.unpack('<5H',cp_span(cp,0x4c03a4,10))}|{0x4c082e}
    cases=[]
    for rate in (0,1,2,4):
        em=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        for page in (0x4d8000,0x4c0000):
            em.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);em.mem_write(page,cp_span(cp,page,4096))
        root,instance=0x21000000,0x22000000
        em.mem_map(root,8192,u.UC_PROT_READ|u.UC_PROT_WRITE);em.mem_map(instance,4096,u.UC_PROT_READ)
        initial=bytearray(b'\xa5'*8192)
        struct.pack_into('<I',initial,0x2c,rate);struct.pack_into('<I',initial,0x3d4,0)
        em.mem_write(root,bytes(initial));em.mem_write(instance,struct.pack('<I',root))
        for reg,value in ((a.UC_ARM_REG_R10,instance),(a.UC_ARM_REG_R11,root)):
            em.reg_write(reg,value)
        trace=[];stopped=[];phase=['projection']
        def instruction(vm,addr,size,_):
            stops={0x4d8382} if phase[0]=='projection' else targets
            if addr in stops:stopped.append(addr);vm.emu_stop();return
            allowed=((0x4d80d2,0x4d80ee),(0x4d836e,0x4d8382)) if phase[0]=='projection' else ((0x4c0392,0x4c03a4),)
            if not contains(allowed,addr,size):raise ValueError('Unreviewed rate projection instruction.')
            trace.append((addr,size))
        def memory(vm,access,addr,size,value,_):
            locations={(root+0x11cc,4),(root+0x122c,4)} if access==u.UC_MEM_WRITE else {(instance,4),(root+0x3d4,4),(root+0x2c,4),(root+0x11cc,4)}
            table=phase[0]=='selector' and access==u.UC_MEM_READ and size==2 and 0x4c03a4<=addr<0x4c03ae
            if (addr,size) not in locations and not table:raise ValueError('Unexpected rate projection memory access.')
        em.hook_add(u.UC_HOOK_CODE,instruction);em.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        em.emu_start(0x4d80d3,0,count=100,timeout=1_000_000)
        expected=bytearray(initial);struct.pack_into('<I',expected,0x11cc,rate);struct.pack_into('<I',expected,0x122c,0)
        if stopped!=[0x4d8382] or bytes(em.mem_read(root,8192))!=expected:raise ValueError('Rate projection differs.')
        phase[0]='selector';stopped.clear();em.reg_write(a.UC_ARM_REG_R0,root+0xe18)
        em.emu_start(0x4c0393,0,count=100,timeout=1_000_000)
        if len(stopped)!=1:raise ValueError('Selector prefix did not terminate.')
        target=0x4c082e if rate<2 else 0x4c03a4+2*struct.unpack('<H',cp_span(cp,0x4c03a4+(rate-2)*2,2))[0]
        if stopped[0]!=target:raise ValueError('Rate selector branch differs.')
        cases.append(dict(synthetic_normalized_rate=rate,selector_rate_field=rate,selector_branch=hex(target),
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in trace)).hexdigest()))
    return dict(schema='a7c2-cp-rate-projection-fragments/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_snapshot_3d4=0,precondition_mode_and_rate3_helpers_executed=False,
        fragments_executed_separately=True,unknown_helpers_stubbed=0,camera_io=False,installable=False)
