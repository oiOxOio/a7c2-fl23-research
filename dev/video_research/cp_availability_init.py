"""Original post-base constructor, handle binding and movie queries in offline RAM.

This verifies the graph's original initialization, not its current camera state.
Base-constructor execution, boot order and privileged runtime are not invented.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span
from request_emulation import CODE,MODE_TABLE,VTABLE,HANDLE,EXCLUSION,contains

OBJECT=0x18aee1c
TABLE_OBJECT=OBJECT+0x68c
TABLE_FIELDS={0:0xdeac48,0x10:0x25dc04c,0x14:0xde9a4c,0x18:0xee01d2,
    0x1c:0xdea8d4,0x20:0xee0abe,0x24:0xde9ca4,0x28:0xde9fec,
    0x2c:0xdea154,0x30:0xdea424,0x34:0xee01d6,0x38:0xee064a,
    0x3c:0xdea6f4,0x40:0xdeac1c,0x44:0xee0c62}


def inspect(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    return dict(schema='a7c2-cp-availability-init-static/1',cp_sha256=CP_SHA,
        object=hex(OBJECT),handle=hex(HANDLE),
        initialization_entry='0x98cc7e; 0x98cc88/0x98cc90 select object; 0x98ccd6 calls constructor',
        post_base_constructor='0x98bcce..0x98beb8',vtable=hex(VTABLE),vtable_store='0x98bcd8',
        embedded_table_object=hex(TABLE_OBJECT),table_constructor='0x98ccf4 -> 0x98d878',
        table_pointer_store='0x98bea8; receiver+0x684 = receiver+0x68c',
        original_table_fields={hex(k):hex(v) for k,v in TABLE_FIELDS.items()},
        frame_record_consumers=dict(vtable='0xdeac48',
            per_mode_dispatch='slot +0x10 -> 0x98df2c; +0x18 -> 0x98cd86 obtains output record',
            override='slot +0xc -> 0x39c468 -> 0x131888 at 0x39c482',
            output_base='table object +0x10 = 0x25dc04c; 0x170-byte stride',
            geometry_a='table object +0x34 -> per-mode 0x26 bytes -> output +0x4c',
            geometry_b='table object +0x38 -> per-mode 0x26 bytes -> output +0x72',
            timing_helper='0x131490 combines original metadata with caller request fields',
            output_allocation_ownership_verified=False,
            physical_clock_and_timing_units_verified=False,
            dynamic_request_values_verified=False),
        comparison_selector=dict(normalized_rate=2,dispatch_branch='0x4c084a',call='0x4c085e',callee='0x4c00ec',format=3),
        count=30,count_argument='0x98bd6e',mode_table=hex(MODE_TABLE),
        count_and_table_store='0x98d890 stores r1/r2 to table +4/+8',
        handle_binding='0x98a4b2 -> 0x98bcb4 returns 0x18aee1c; 0x98a4c2 writes handle',
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((0x98cc7e,0x98ccf4),(0x98bcb4,0x98bcbe),(0x98bcce,0x98beb8),
                         (0x98ccf4,0x98cd72),(0x98d878,0x98d8c8),(0x98a4b2,0x98a4c6),
                         (0x4c084a,0x4c0862),(0x4c00ec,0x4c0328),
                         (0x98df2c,0x98df72),(0x98cd86,0x98cd9e),(0x39c468,0x39c486),
                         (0x131888,0x13199c),(0x98cfde,0x98cfe8),(0x39affc,0x39b014),(0x39b0ec,0x39b0fe),(0x39ae64,0x39ae9a))],
        submission_gate=dict(virtual_slot='0x24 -> 0x98cfde -> 0x10c -> 0x39affc',
            gate='receiver +0x6e8',constructor_clear='0x98beb4',zero_path='0x39b00c..0x39b012 -> 0x39b0ec',
            zero_result=0,zero_path_mode_lookup_or_staging=False,
            enable_store='0x39ae96 follows OS/driver initialization; not executed',disable_store='0x39af84'),
        static_initializer_binding_verified=True,boot_execution_verified=False,
        base_constructor_executed=False,camera_io=False,installable=False)


def run_original(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    ctor=((0x98bcce,0x98beb8),(0x98ccf4,0x98cd72),(0x98d878,0x98d8c8))
    binding=((0x98a4b2,0x98a4c6),(0x98bcb4,0x98bcbe))
    selector=tuple(CODE[k] for k in ('instance','dispatch','availability','lookup'))+((0xb29ab0,0xb29c20),(0x4c00ec,0x4c0328))
    submission=((0x98df2c,0x98df72),(0x98cd86,0x98cd9e),(0x39c468,0x39c486),
                         (0x131888,0x13199c),(0x98cfde,0x98cfe8),(0x39affc,0x39b014),(0x39b0ec,0x39b0fe))
    cases=[]
    for rate,flag in ((0,0),(0,1),(2,0),(2,1)):
        em=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        pages=set()
        for lo,hi in (*ctor,*binding,*selector,*submission,(MODE_TABLE,MODE_TABLE+120),(VTABLE,VTABLE+0xd8)):
            pages.update(range(lo&~4095,(hi+4095)&~4095,4096))
        for page in pages:
            em.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);em.mem_write(page,cp_span(cp,page,4096))
        ram=HANDLE&~4095
        em.mem_map(ram,8192,u.UC_PROT_READ|u.UC_PROT_WRITE);em.mem_write(ram,b'\xa5'*8192)
        em.mem_map(EXCLUSION&~4095,4096,u.UC_PROT_READ);em.mem_write(EXCLUSION,bytes(2))
        stack,sp,stop=0x21000000,0x21002000,0x30000000
        em.mem_map(stack,0x4000,u.UC_PROT_READ|u.UC_PROT_WRITE);em.mem_write(stack,b'\xa5'*0x4000)
        em.mem_map(stop,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        phase=['constructor'];trace=[];stopped=[];queries=[]
        def instruction(vm,addr,size,_):
            stops={0x98beb8} if phase[0]=='constructor' else {stop,0xb29bf6,0x4c02fe}
            if addr in stops:stopped.append(addr);vm.emu_stop();return
            reviewed=ctor if phase[0]=='constructor' else binding if phase[0]=='binding' else submission if phase[0]=='submission' else selector
            if not contains(reviewed,addr,size):raise ValueError('Unreviewed initialization/query instruction.')
            if addr==0x989e8a:queries.append(vm.reg_read(a.UC_ARM_REG_R1))
            trace.append((addr,size))
        def memory(vm,access,addr,size,value,_):
            ranges=((sp-0x100,sp+0x38),)
            if phase[0]=='constructor':ranges+=((OBJECT,OBJECT+0x6e9),)
            elif phase[0]=='binding':ranges+=((HANDLE,HANDLE+4),)
            elif phase[0]=='submission' and access==u.UC_MEM_READ:ranges+=((OBJECT,OBJECT+4),(OBJECT+0x6e8,OBJECT+0x6e9),(VTABLE+0x10c,VTABLE+0x110))
            elif access==u.UC_MEM_READ:ranges+=((HANDLE,HANDLE+4),(OBJECT,OBJECT+4),
                (OBJECT+0x684,OBJECT+0x688),(TABLE_OBJECT+4,TABLE_OBJECT+12),
                (MODE_TABLE,MODE_TABLE+120),(VTABLE+0xd4,VTABLE+0xd8),(EXCLUSION,EXCLUSION+2))
            branch_table=phase[0]=='selector' and access==u.UC_MEM_READ and size==1 and (0x4c017a<=addr<0x4c017e or 0x4c0214<=addr<0x4c0218)
            if not contains(ranges,addr,size) and not branch_table:raise ValueError('Unexpected initializer/query memory access.')
        em.hook_add(u.UC_HOOK_CODE,instruction);em.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        em.reg_write(a.UC_ARM_REG_SP,sp);em.reg_write(a.UC_ARM_REG_R4,OBJECT)
        em.emu_start(0x98bccf,0,count=1000,timeout=1_000_000)
        if stopped!=[0x98beb8] or em.reg_read(a.UC_ARM_REG_SP)!=sp:raise ValueError('Constructor fragment did not finish.')
        checks=((OBJECT,VTABLE),(OBJECT+0x684,TABLE_OBJECT),(TABLE_OBJECT+4,30),(TABLE_OBJECT+8,MODE_TABLE))+tuple((TABLE_OBJECT+off,value) for off,value in TABLE_FIELDS.items())
        for addr,value in checks:
            if struct.unpack('<I',em.mem_read(addr,4))[0]!=value:raise ValueError('Original constructed graph differs.')
        phase[0]='binding';stopped.clear();em.reg_write(a.UC_ARM_REG_LR,stop|1)
        em.emu_start(0x98a4b3,0,count=100,timeout=1_000_000)
        if stopped!=[stop] or struct.unpack('<I',em.mem_read(HANDLE,4))[0]!=OBJECT:raise ValueError('Handle binding differs.')
        # Freeze graph built by ORIGINAL stores, not a host-populated pointer graph.
        em.mem_protect(ram,8192,u.UC_PROT_READ)
        phase[0]='selector';stopped.clear()
        for reg,value in ((a.UC_ARM_REG_R0,flag),(a.UC_ARM_REG_R1,3),(a.UC_ARM_REG_R2,0),
                          (a.UC_ARM_REG_R3,0),(a.UC_ARM_REG_LR,stop|1)):
            em.reg_write(reg,value)
        em.emu_start(0xb29ab1 if rate==0 else 0x4c00ed,0,count=2000,timeout=1_000_000)
        success=bool(flag or rate==2);expected_mode=0x821 if flag else 0x880
        if stopped!=[stop if success else 0xb29bf6]:raise ValueError('Constructed graph query outcome differs.')
        if success and (em.reg_read(a.UC_ARM_REG_R0)!=expected_mode or em.reg_read(a.UC_ARM_REG_SP)!=sp):raise ValueError('Initialized selector return differs.')
        # Genuine constructor state is still disabled. Do not fabricate readiness.
        graph_before=bytes(em.mem_read(ram,8192))
        if em.mem_read(OBJECT+0x6e8,1)!=bytes(1):raise ValueError('Constructor gate is not zero.')
        phase[0]='submission';stopped.clear()
        # No request page is mapped: disabled original path must not dereference it.
        for reg,value in ((a.UC_ARM_REG_R0,OBJECT),(a.UC_ARM_REG_R1,0x22000000),
                          (a.UC_ARM_REG_SP,sp),(a.UC_ARM_REG_LR,stop|1)):
            em.reg_write(reg,value)
        em.emu_start(0x98cfdf,0,count=100,timeout=1_000_000)
        if stopped!=[stop] or em.reg_read(a.UC_ARM_REG_R0)!=0 or em.reg_read(a.UC_ARM_REG_SP)!=sp:
            raise ValueError('Disabled submission path differs.')
        if bytes(em.mem_read(ram,8192))!=graph_before:raise ValueError('Disabled submission changed graph.')
        for lo,hi in ((stack,sp-0x100),(sp+0x38,stack+0x4000),
                      (ram,HANDLE),(HANDLE+4,OBJECT),(OBJECT+0x6e9,ram+8192)):
            if bytes(em.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Initialization/query canary differs.')
        cases.append(dict(declared_normalized_rate_branch=rate,synthetic_flag=flag,original_queries=[hex(q) for q in queries],
            returned_mode=hex(expected_mode) if success else None,stopped_before_diagnostic=not success,
            original_submission_gate=0,disabled_virtual_submission_result=0,
            submission_request_dereferenced=False,submission_mode_lookup_or_staging_executed=False,
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in trace)).hexdigest()))
    return dict(schema='a7c2-cp-availability-init-fragments/1',cp_sha256=CP_SHA,cases=cases,
        original_graph_construction_executed=True,original_handle_binding_executed=True,
        original_table_fields_verified={hex(k):hex(v) for k,v in TABLE_FIELDS.items()},
        synthetic_zero_exclusion=True,synthetic_initial_ram=True,base_constructor_executed=False,
        boot_execution_verified=False,unknown_helpers_stubbed=0,camera_io=False,installable=False)
