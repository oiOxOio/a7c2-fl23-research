"""Original CP request-buffer copies; not proof of a live submission chain.

The selected mode tag and surrounding payload are synthetic. Original copy
instructions and ARM memcpy execute unchanged; branch gates are not forced.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span
from cp_snapshot_emulation import COPY
ROOT=0x172fe50
LENGTH=0x304
RANGES=((0xb2ede8,0xb2ee16),(0x4d6dce,0x4d6de2),
    (0x4d6b92,0x4d6b9e),(0x4be1a4,0x4be242),(0xb2ddb4,0xb2ddd8),(0xb2ebe0,0xb2ebe6),
    (0xb2a5c6,0xb2a606),(0xb2a86e,0xb2a876),(0xb2ede2,0xb2ede8),(0x4ce90a,0x4ce972),(0xb0924c,0xb0929c),
    (0xb092bc,0xb092d4),(0x989fa0,0x989fda),(0x4c79c0,0x4c79d8),
    (0x4c7bc2,0x4c7bea),(0xb28c5c,0xb28c74),(0x4bf138,0x4bf174),
    (0x4dbdb6,0x4dbdca),(0x4dbe1c,0x4dbed6),(0x4dbf7e,0x4dbf96),(0xb28fe6,0xb29054),
    (0xb2a58e,0xb2a5c6),(0x4de300,0x4de348),(0xb29262,0xb2928c),(0x4be004,0x4be074),
    (0x46e8b2,0x46e8d0),(0x46ed42,0x46ed5e),(0xb0dd6e,0xb0dd74),(0xb2a46a,0xb2a480),
    (0x98cfd4,0x98cfe8),(0x989d4a,0x989d54),(0xde98c0,0xde98c8),(0xde99ac,0xde99b4),
    (0xb29504,0xb29512),(0xb29366,0xb29384),(0xb2b4ac,0xb2b4b2))


def inspect(cp:bytes)->dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    return dict(schema='a7c2-cp-request-handoff-static/1',cp_sha256=CP_SHA,
        snapshot_root=hex(ROOT),generated_offset='0x1144',staged_offset='0x1448',current_offset='0xe38',
        copy_length=LENGTH,
        generated_to_staged='0xb2ede8..0xb2ee12 copies root+0x1144 to root+0x1448',
        staged_to_current='0x4d6dce..0x4d6dde copies root+0x1448 to root+0xe38; preceding root+0x17e9 gate must be nonzero',
        callback_binding='default branch 0xb2a5e2..0xb2a5ea stores 0x4be1a5 into generated record+0x44; callback wrapper 0xb2a86e invokes tuple+8',
        mode_consumer=dict(entry='0x4be1a4',instance_getter='0xb2ddb4 -> 0x173efe8',
            choice='instance+0xc+0x20 or +0x630 selected by runtime conditions',
            resolved_snapshot_choices=['0xe38','0x1448'],
            store='0x4be21e loads selected record word; 0x4be22e writes receiver+0x564'),
        sync_candidate=dict(entry='0x4ce7bc',mode_load='0x4ce90a loads receiver+0x564',
            handoff='0x4ce96a..0x4ce96e -> 0xb092bc',
            independent_buffer='0x1109ecc; 0xb092cc stores input mode word',
            state_gate='0xb0924c uses state at 0x1109ed4; when old<3, stores 3 then jumps to 0x989fa0 with buffer',
            api='0x989fa0 diagnostic SetModeSync; not SetModeAsync',
            default_constructed_driver_path='handle 0x18aeb8c -> object 0x18aee1c, constructor vtable 0xde98a0; +0x20 -> 0x98cfd4 sets r2=0 -> virtual +0x10c -> 0x39affc',
            sync_async_distinction='same default driver entry; Async slot +0x24 -> 0x98cfde sets r2=1; neither bypasses receiver+0x6e8 readiness',
            live_driver_readiness_verified=False,
            static_receiver_identity_path_proven=True,
            receiver_path='4dbeac root+0x146c=staged+0x24 -> 4dbf92 b28ee2; b29030 +0x18 -> record+0x3c init tuple -> 4bdf88 allocates and calls init with object; b2903e forwards returned object -> 46e8b2 stores owner[0]; 46ed42 main callback -> 4c79c0 reads owner[0] -> Sync queue receiver',
            init_callback_is_synchronous_not_queued=True,
            receiver_alias_and_callback_lifecycle_verified=False,
            actual_state_transition_verified=False,device_call_executed=False),
        gated_evidence_dag=[
            dict(edge='generator default movie callback 0x4c79c1 -> record+0x38=0',proof='0xb2a58e..0xb2a5c4 compares only 0x4c4691/0x4c33f5/0x4c1129 for value 1'),
            dict(edge='0x4de330 -> 0xb2919e',status='rejected for default movie tuple',gate='0x4de30e requires staged+0x38 == 1, incompatible with movie value zero'),
            dict(edge='0x4dbeac -> 0x4dbf92 -> 0xb28ee2',status='static conditionally compatible, live conditions unverified',gates=['root+0x1480 (staged+0x38) == 0','prior helper-derived r5 != 0','root+0x17e9 != 0','global 0x1b1e1fa == 0','prior local exclusion flag bit0 == 0','root+0x1757 OR +0x1759 nonzero, OR descriptor +0x19b4 bit12, OR global 0x1a533a4+0x2a == 1']),
            dict(edge='0xb29030 -> 0x4bdf88 -> 0x46e884',status='static object identity proven on successful allocation/return path',gates=['non-null input stage tuple','context allocation success','initialization callback returns','stage-owner allocation success']),
            dict(edge='0x46ed42 -> 0x4c79c0 -> Sync queue',status='static owner/receiver provenance, live dispatch and ordering unverified',gates=['owner+0x26 nonzero','scheduler delivers owner','movie-stage state/branch conditions permit queue registration']),
            dict(edge='0x4ce7bc -> 0xb092bc -> 0x989fa0 -> default 0x39affc',status='static submission route, not physical execution',gates=['callback conditions permit handoff','0x1109ed4 old state < 3','default constructed driver remains selected','driver+0x6e8 nonzero'])],
        queue_coordinates=dict(sync_registration='0x4c79d0 owner[0] -> fp; 0x4c7bc8/0x4c7be6 passes that receiver and callback tuple to 0xb28c5c',
            indexed_queue='0xb28c5c selects queue 3; 0x4bf148 saves receiver at payload+0x14; 0xb29504..0xb29510 copies payload to node+8',
            dispatch='0xb2936e loads receiver from node+0x1c, secondary argument from node+0x20; wrapper forwards receiver into r0',
            init_callback_not_a_queue_node=True,actual_queue_order_proven=False),
        previous_request_generator_to_setmodeasync_claim_retracted=True,
        ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest()) for lo,hi in RANGES],
        continuous_execution_verified=False,recording_verified=False,camera_io=False,installable=False)


def run_copies(cp:bytes)->dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
    fragments=((0xb2ede8,0xb2ee16),(0x4d6dce,0x4d6de2))
    for page in sorted({lo&~4095 for lo,hi in (*fragments,COPY)}):
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,4096))
    base=ROOT&~4095;end=(ROOT+0x1800+4095)&~4095
    uc.mem_map(base,end-base,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(base,b'\xa5'*(end-base))
    stack,sp=0x20000000,0x20000800
    uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(stack,b'\xa5'*4096)
    payload=struct.pack('<I',0x821)+bytes((i*37+11)&255 for i in range(LENGTH-4))
    uc.mem_write(ROOT+0x1144,payload)
    uc.reg_write(a.UC_ARM_REG_R2,0x1558) # Exact live-in from preceding original MOVW at 0xb2ede2.
    uc.reg_write(a.UC_ARM_REG_SP,sp);uc.reg_write(a.UC_ARM_REG_R11,ROOT)
    traces=[];active=[0];stops=[]
    def code(em,pc,size,_):
        lo,hi=fragments[active[0]]
        if pc==hi:stops.append(pc);em.emu_stop();return
        if not (lo<=pc and pc+size<=hi or COPY[0]<=pc and pc+size<=COPY[1]):raise ValueError('Unreviewed handoff instruction.')
        thumb=bool(em.reg_read(a.UC_ARM_REG_CPSR)&32)
        if thumb==(COPY[0]<=pc<COPY[1]):raise ValueError('Unexpected copy instruction set.')
        traces.append((pc,size))
    def memory(em,access,addr,size,value,_):
        src,dst=((ROOT+0x1144,ROOT+0x1448),(ROOT+0x1448,ROOT+0xe38))[active[0]]
        ranges=[(sp-16,sp+16)]
        ranges.append((src,src+LENGTH) if access==u.UC_MEM_READ else (dst,dst+LENGTH))
        if access==u.UC_MEM_READ and active[0]==0:ranges.extend((ROOT+x,ROOT+x+1) for x in (0x1558,0x1555,0x1556))
        if not any(lo<=addr and addr+size<=hi for lo,hi in ranges):raise ValueError(f'Unexpected handoff memory access {addr:#x}+{size} at {em.reg_read(a.UC_ARM_REG_PC):#x}.')
    uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
    cases=[]
    for index,(start,stop) in enumerate(fragments):
        active[0]=index
        if index==1:uc.reg_write(a.UC_ARM_REG_R10,ROOT)
        before=bytes(uc.mem_read(base,end-base));old_trace=len(traces)
        uc.emu_start(start|1,0,count=10000,timeout=1_000_000)
        dst=ROOT+(0x1448 if index==0 else 0xe38)
        if stops[-1:]!=[stop] or bytes(uc.mem_read(dst,LENGTH))!=payload:raise ValueError('Original handoff copy differs.')
        after=bytes(uc.mem_read(base,end-base));expected=bytearray(before);expected[dst-base:dst-base+LENGTH]=payload
        if after!=bytes(expected):raise ValueError('Handoff changed bytes outside destination.')
        cases.append(dict(source=hex(ROOT+(0x1144 if index==0 else 0x1448)),destination=hex(dst),length=LENGTH,
            instructions=len(traces)-old_trace,mode_word=hex(struct.unpack('<I',uc.mem_read(dst,4))[0])))
    return dict(schema='a7c2-cp-request-handoff-original-copies/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_source_payload=True,first_fragment_r2_live_in='0x1558 from original 0xb2ede2',mode_tag_not_live_selection=True,
        original_arm_memcpy_executed=True,fragments_executed_separately=True,
        preceding_branch_gates_executed=False,callback_lifecycle_executed=False,
        instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in traces)).hexdigest(),
        setmode_sync_executed=False,setmode_async_executed=False,camera_io=False,installable=False)


def run_queue_dispatch(cp:bytes)->dict:
    """Execute original queue dispatch/wrappers on declared synthetic nodes.

    This verifies argument coordinates, not node allocation, enqueue, live queue
    order, object identity, or either callback body.
    """
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for wrapper,target,has_second in ((0xb2b4ac,0x4ce7bc,False),):
        uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        ranges=((0xb29366,0xb29384),(wrapper,wrapper+(8 if has_second else 6)))
        for page in sorted({lo&~4095 for lo,hi in ranges}|{target&~4095}):
            uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            uc.mem_write(page,cp_span(cp,page,4096))
        node=0x20000000;context=0x21000000;argument=0x22000000
        uc.mem_map(node,4096,u.UC_PROT_READ)
        contents=struct.pack('<10I',node,node,wrapper|1,0,target|1,0,0,context,argument,0)
        uc.mem_write(node,contents);uc.reg_write(a.UC_ARM_REG_R5,node)
        trace=[];reached=[]
        def code(em,pc,size,_):
            if pc==target:reached.append(pc);em.emu_stop();return
            if not any(lo<=pc and pc+size<=hi for lo,hi in ranges):raise ValueError('Unexpected queue-dispatch instruction.')
            if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Queue dispatch left Thumb state.')
            trace.append((pc,size))
        def memory(em,access,addr,size,value,_):
            if access!=u.UC_MEM_READ or not node+8<=addr or addr+size>node+0x24:raise ValueError('Unexpected queue node access.')
        uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0xb29367,0,count=100,timeout=1_000_000)
        if reached!=[target] or uc.reg_read(a.UC_ARM_REG_R0)!=context:raise ValueError('Queue receiver forwarding differs.')
        if has_second and uc.reg_read(a.UC_ARM_REG_R1)!=argument:raise ValueError('Queue secondary argument differs.')
        cases.append(dict(wrapper=hex(wrapper),callback_entry=hex(target),receiver_source='node+0x1c',
            secondary_argument_source='node+0x20' if has_second else None,
            callback_body_executed=False,instructions=len(trace),
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest()))
    return dict(schema='a7c2-cp-request-queue-dispatch/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_queue_nodes=True,actual_queue_insertion_executed=False,
        actual_receiver_alias_verified=False,actual_callback_order_verified=False,
        camera_io=False,installable=False)


def run_stage_receiver(cp:bytes)->dict:
    """Original init-call, owner-construction and main-call fragments, separately.

    Allocation, callback bodies, scheduling and all branch gates are excluded.
    Synthetic addresses represent allocated objects, not live camera pointers.
    """
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
    fragments=((0x4be026,0x4be04a),(0x46e8b2,0x46e8d0),(0x46ed42,0x46ed5e))
    wrappers=((0xb2a86e,0xb2a876),(0xb0dd6e,0xb0dd74))
    targets=(0x4be1a4,0x46e8d0,0x4c79c0)
    for page in sorted({lo&~4095 for lo,hi in (*fragments,*wrappers)}|{x&~4095 for x in targets}):
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,4096))
    record,context,owner,sp=0x20000000,0x21000000,0x22000000,0x23000800
    for page in (record,owner,sp&~4095):uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
    main=struct.pack('<5I',0xb0dd6f,0,0x4c79c1,0,0)
    init=struct.pack('<5I',0xb2a86f,0,0x4be1a5,0,0)
    uc.mem_write(record+0x24,main);uc.mem_write(record+0x3c,init)
    active=[0];traces=[];stops=[]
    def code(em,pc,size,_):
        if pc==targets[active[0]]:stops.append(pc);em.emu_stop();return
        allowed=(fragments[active[0]],)+(wrappers if active[0]!=1 else ())
        if not any(lo<=pc and pc+size<=hi for lo,hi in allowed):raise ValueError('Unexpected stage receiver instruction.')
        if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Stage receiver left Thumb.')
        traces.append((pc,size))
    def memory(em,access,addr,size,value,_):
        bounds=([(record+0x24,record+0x50),(sp,sp+0x14),(owner,owner+0x28)] if access==u.UC_MEM_READ
            else [(sp,sp+0x14),(owner,owner+0x28)])
        if not any(lo<=addr and addr+size<=hi for lo,hi in bounds):raise ValueError('Unexpected stage receiver memory.')
    uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
    results=[]
    registers=({a.UC_ARM_REG_R11:record+0x3c,a.UC_ARM_REG_R4:context,a.UC_ARM_REG_R8:0},
        {a.UC_ARM_REG_R9:context,a.UC_ARM_REG_R10:owner,a.UC_ARM_REG_R11:record+0x24,
         a.UC_ARM_REG_R6:0,a.UC_ARM_REG_R4:1,a.UC_ARM_REG_R8:0},
        {a.UC_ARM_REG_R4:owner})
    for index,(start,end) in enumerate(fragments):
        active[0]=index;uc.reg_write(a.UC_ARM_REG_SP,sp)
        for reg,value in registers[index].items():uc.reg_write(reg,value)
        before=len(traces);uc.emu_start(start|1,0,count=100,timeout=1_000_000)
        if stops[-1:]!=[targets[index]]:raise ValueError('Stage receiver fragment did not stop.')
        if index==0 and uc.reg_read(a.UC_ARM_REG_R0)!=context:raise ValueError('Init receiver differs.')
        if index==1 and (struct.unpack('<I',uc.mem_read(owner,4))[0]!=context or bytes(uc.mem_read(owner+0xc,20))!=main):raise ValueError('Owner construction differs.')
        if index==2 and uc.reg_read(a.UC_ARM_REG_R0)!=owner:raise ValueError('Main callback owner differs.')
        results.append(dict(start=hex(start),stopped_at=hex(targets[index]),instructions=len(traces)-before))
    return dict(schema='a7c2-cp-stage-receiver-original/1',cp_sha256=CP_SHA,cases=results,
        init_receiver_equals_owner_word_zero=True,main_callback_receives_owner=True,
        synthetic_allocated_objects=True,synthetic_default_callback_tuples=True,
        actual_allocation_executed=False,callback_bodies_executed=False,
        scheduling_executed=False,fragments_executed_separately=True,
        instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in traces)).hexdigest(),
        camera_io=False,installable=False)


def run_builder_gate(cp:bytes)->dict:
    """Original stage-category assignment/default init tuple; no preceding setup."""
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    results=[]
    for callback in (0x4c79c1,0x4c4691,0x4c33f5,0x4c1129):
        uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB);page=0xb2a000;out=0x20000000
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,4096))
        uc.mem_map(out,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
        uc.mem_write(out,b'\xa5'*4096);uc.reg_write(a.UC_ARM_REG_R4,callback);uc.reg_write(a.UC_ARM_REG_R6,out)
        trace=[];stops=[]
        def code(em,pc,size,_):
            if pc==0xb2a606:stops.append(pc);em.emu_stop();return
            if not 0xb2a58e<=pc or pc+size>0xb2a606:raise ValueError('Unexpected builder-gate instruction.')
            if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Builder gate left Thumb.')
            trace.append((pc,size))
        def memory(em,access,addr,size,value,_):
            if access!=u.UC_MEM_WRITE or not out+0x38<=addr or addr+size>out+0x64:raise ValueError('Unexpected builder-gate memory.')
        uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0xb2a58f,0,count=100,timeout=1_000_000)
        flag=struct.unpack('<I',uc.mem_read(out+0x38,4))[0]
        if stops!=[0xb2a606] or flag!=int(callback!=0x4c79c1):raise ValueError('Original builder category differs.')
        if struct.unpack('<5I',uc.mem_read(out+0x3c,20))!=(0xb2a86f,0,0x4be1a5,0,0):raise ValueError('Original default init tuple differs.')
        results.append(dict(stage_callback=hex(callback),record_38=flag,
            original_init_callback='0x4be1a5',instructions=len(trace),
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest()))
    return dict(schema='a7c2-cp-builder-category-original/1',cp_sha256=CP_SHA,cases=results,
        declared_callback_inputs=True,preceding_selector_executed=False,
        default_movie_4de330_route_rejected=True,camera_io=False,installable=False)
