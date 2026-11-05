"""Pinned AP caution/warning registration/condition evidence; numeric enum meaning stays qualified.

GOT loads and the actual index*0xa0,+0x10 consumer determine record alignment.
Do not align records by visually appealing packed words or infer enums from name order.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE,AP_SHA,Elf64,check_image,span
from ap_xrefs import got_pointer_loads,relative_relocations

GOT=0x5ba52f8
TABLE=0x58f03a8
STRIDE=0xa0
COUNT=0x36c
NAMES=0x57fd340
RECORDS={193:(0x3784d30,0x1871eb8),194:(0x3784708,0x1871ef8),
         222:(0x3784428,0x1870400),229:(0x377eab0,0x18727c4)}


def name_at(elf: Elf64,index: int) -> dict:
    if type(index) is not int or not 0<=index<65536:
        raise ValueError('Name index must be a bounded unsigned integer.')
    slot=NAMES+index*8
    pointer=struct.unpack('<Q',span(elf.data,elf.file_offset(slot,8),8))[0]
    off=elf.file_offset(pointer,1)
    end=elf.data.find(b'\0',off,min(len(elf.data),off+1025))
    if end<0:raise ValueError('Missing bounded name terminator.')
    elf.file_offset(pointer,end-off+1)
    return dict(index=hex(index),slot=hex(slot),string_va=hex(pointer),
        name=elf.data[off:end].decode('ascii'),
        string_sha256=hashlib.sha256(elf.data[off:end+1]).hexdigest())


def condition_pairs(elf: Elf64,pointer: int) -> list[dict]:
    pairs=[]
    for index in range(64):
        off=elf.file_offset(pointer+index*8,8)
        prop,value=struct.unpack('<II',span(elf.data,off,8))
        if prop==0x80000000:
            if value!=0x80000001:raise ValueError('Unexpected condition end marker.')
            return pairs
        if prop>=65536 or (value>=65536 and value!=0x80000001):
            raise ValueError('Unsupported condition pair encoding.')
        pairs.append(dict(property=name_at(elf,prop),value_word=hex(value),
            value_name=name_at(elf,value) if value<65536 else None,
            marker_semantics_verified=False))
    raise ValueError('Condition list exceeds reviewed bound.')


def inspect(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP')
    elf=Elf64(ap)
    if struct.unpack('<Q',span(ap,elf.file_offset(GOT,8),8))[0]!=TABLE:
        raise ValueError('Registration GOT link-time value differs.')
    rows=[]
    for index,(condition,callback) in RECORDS.items():
        va=TABLE+index*STRIDE;off=elf.file_offset(va,STRIDE)
        raw=span(ap,off,STRIDE)
        if struct.unpack_from('<Q',raw,0)[0]!=condition or struct.unpack_from('<Q',raw,16)[0]!=callback:
            raise ValueError('Registration pointer fields differ.')
        co=elf.file_offset(condition,16)
        prop,value=struct.unpack('<II',span(ap,co,8))
        pairs=condition_pairs(elf,condition)
        rows.append(dict(index=index,record_va=hex(va),record_file_offset=hex(off),
            stride=STRIDE,callback_field_offset=16,callback=hex(callback),
            condition_pointer=hex(condition),condition_pair=[name_at(elf,prop),name_at(elf,value)],
            condition_pairs=pairs,
            marker_semantics_verified=False,record_sha256=hashlib.sha256(raw).hexdigest()))
    return dict(schema='a7c2-ap-registration/1',ap_sha256=AP_SHA,
        subsystem='caution/warning; not a restriction enforcement registry',
        caution_source_literal='0x378775e',caution_function_literal='0x3787830',
        restriction_enforcement_verified=False,table_base=hex(TABLE),count_bound=COUNT,count_compare_va='0x1882fac',
        got=hex(GOT),got_loads=got_pointer_loads(elf,{GOT}),
        got_relocation=relative_relocations(elf,{TABLE}),records=rows,
        callback_relocations=relative_relocations(elf,set(c for _,c in RECORDS.values())),
        name_index_consumers=[dict(va=hex(va),sha256=hashlib.sha256(
            span(ap,elf.file_offset(va,n),n)).hexdigest())
            for va,n in ((0x35ae788,0x54),(0x35ae83c,4))],
        predicate_interpretation='Record 193 compares getter state to 1; record 194 additionally checks another model field. Their descriptor pairs explicitly name APSC conditions. Record 222 associates format predicate 7 with XAVC S 4K; record 229 names 60P and references both FF/APSC restriction composite keys.',
        apsc_value_one_association='static caution/warning association, not a complete enum-definition proof',
        full_value_zero_verified=False,runtime_registration_index_verified=False,
        movie_path_verified=False,recording_verified=False,camera_io=False,installable=False)


def run_original(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP')
    elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    def original_page(uc,va,executable=True):
        page=va & ~4095
        uc.mem_map(page,4096,u.UC_PROT_READ | (u.UC_PROT_EXEC if executable else 0))
        uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
    cases=[]
    for index,(_,callback) in RECORDS.items():
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        original_page(uc,0x1883160)
        for address in (GOT,TABLE+index*STRIDE):original_page(uc,address,False)
        stack,inp,sp=0x10000000,0x20000000,0x10000800
        uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
        uc.mem_write(stack,b'\xa5'*4096)
        uc.mem_map(inp,4096,u.UC_PROT_READ)
        uc.mem_write(inp,struct.pack('<H',index))
        uc.reg_write(a.UC_ARM64_REG_SP,sp);uc.reg_write(a.UC_ARM64_REG_X1,inp)
        stopped=[]
        def instruction(em,address,size,unused):
            if address==0x1883190:stopped.append(address);em.emu_stop();return
            if not 0x1883160<=address<0x1883190:raise ValueError('Unreviewed registration instruction.')
        def memory(em,access,address,size,value,unused):
            ranges=((sp-64,64),) if access==u.UC_MEM_WRITE else ((inp,2),(GOT,8),(TABLE+index*STRIDE+16,8))
            if not any(lo<=address and address+size<=lo+n for lo,n in ranges):
                raise ValueError('Unexpected registration memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction)
        uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x1883160,0,count=100,timeout=1_000_000)
        if stopped!=[0x1883190] or uc.reg_read(a.UC_ARM64_REG_X0)!=callback:
            raise ValueError('Unexpected registration callback selection.')
        if uc.reg_read(a.UC_ARM64_REG_SP)!=sp-64:raise ValueError('Unexpected registration stack.')
        for lo,hi in ((stack,sp-64),(sp,stack+4096)):
            if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Registration stack canary changed.')
        cases.append(dict(synthetic_index=index,selected_callback=hex(callback),
            stopped_before='0x1883190',callback_executed=False,load_bias_assumption=0))
    # Separate fragment: start AFTER an unknown lock helper, stop BEFORE unlock.
    predicates=[]
    for value in (0,1,2):
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for address in (0x1871ed0,0x285d6d0):original_page(uc,address)
        state=0x7e59d18
        uc.mem_map(state & ~4095,4096,u.UC_PROT_READ)
        uc.mem_write(state,struct.pack('<I',value))
        uc.reg_write(a.UC_ARM64_REG_X20,0x20000000)
        stopped=[]
        def instruction(em,address,size,unused):
            if address==0x1871ee4:stopped.append(address);em.emu_stop();return
            if not (0x1871ed0<=address<0x1871ee4 or 0x285d6d0<=address<0x285d6e4):
                raise ValueError('Unreviewed predicate instruction.')
        def memory(em,access,address,size,value_written,unused):
            if access!=u.UC_MEM_READ or (address,size)!=(state,4):
                raise ValueError('Unexpected predicate memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction)
        uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x1871ed0,0,count=100,timeout=1_000_000)
        result=uc.reg_read(a.UC_ARM64_REG_X20)
        if stopped!=[0x1871ee4] or result!=int(value==1):raise ValueError('Unexpected predicate result.')
        predicates.append(dict(synthetic_model_value=value,predicate_result=result,
            stopped_before='0x1871ee4',locking_helpers_executed=False))
    return dict(schema='a7c2-ap-registration-fragments/1',ap_sha256=AP_SHA,
        subsystem='caution/warning',restriction_enforcement_verified=False,
        registration_cases=cases,predicate_cases=predicates,fragments_executed_separately=True,
        reviewed_ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(
            span(ap,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest())
            for lo,hi in ((0x1883160,0x1883190),(0x1871ed0,0x1871ee4),(0x285d6d0,0x285d6e4))],
        runtime_registration_index_verified=False,full_value_zero_verified=False,
        camera_io=False,firmware_file_written=False,movie_path_verified=False,
        recording_verified=False,installable=False)


def run_rate_original(ap: bytes) -> dict:
    """Separate original predicate fragments; no lock stubs or menu mutation."""
    check_image(ap,AP_SIZE,AP_SHA,'AP')
    elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    format_state=0x7e50000+0x4d8+0x1c000+0x700
    rate_state=0x7e50000+0x4d8+0x1c000+0x7a0
    alternate_state=0x7e50000+0x4d8+0xac000+0xd60
    getter_ranges=((0x286608c,0x28660a0),(0x286612c,0x2866140),(0x2894bf0,0x2894c04))
    cases=[]
    for phase in ('format_predicate','rate_predicate'):
        vectors=((6,0),(7,0),(8,0)) if phase=='format_predicate' else ((7,0),(7,1),(7,2))
        start,stop=(0x1870418,0x187042c) if phase=='format_predicate' else (0x18727dc,0x18728b4)
        for format_value,rate_value in vectors:
            uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
            for page in {start & ~4095,*(lo & ~4095 for lo,_ in getter_ranges)}:
                uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
                uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
            for page in {format_state & ~4095,rate_state & ~4095,alternate_state & ~4095}:
                uc.mem_map(page,4096,u.UC_PROT_READ)
            for address,value in ((format_state,format_value),(rate_state,rate_value),(alternate_state,0)):
                uc.mem_write(address,struct.pack('<I',value))
            stopped=[];count=[0]
            def instruction(em,address,size,unused):
                count[0]+=1
                if address==stop:stopped.append(address);em.emu_stop();return
                if not (start<=address<stop or any(lo<=address<hi for lo,hi in getter_ranges)):
                    raise ValueError('Unreviewed rate predicate instruction.')
            def memory(em,access,address,size,value,unused):
                if access!=u.UC_MEM_READ or address not in (format_state,rate_state,alternate_state) or size!=4:
                    raise ValueError('Unexpected rate predicate memory access.')
            uc.hook_add(u.UC_HOOK_CODE,instruction)
            uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(start,0,count=200,timeout=1_000_000)
            reg=a.UC_ARM64_REG_X20 if phase=='format_predicate' else a.UC_ARM64_REG_X19
            result=uc.reg_read(reg)
            expected=int(format_value==7) if phase=='format_predicate' else int(rate_value==0)
            if stopped!=[stop] or result!=expected:raise ValueError('Unexpected rate predicate result.')
            cases.append(dict(phase=phase,synthetic_format_value=format_value,
                synthetic_rate_value=rate_value,synthetic_alternate_value=0,
                predicate_result=result,stopped_before=hex(stop),instructions=count[0]-1))
    return dict(schema='a7c2-ap-format-rate-predicates/1',ap_sha256=AP_SHA,cases=cases,
        subsystem='caution/warning',restriction_enforcement_verified=False,
        state_addresses=dict(format=hex(format_state),rate=hex(rate_state),alternate=hex(alternate_state)),
        reviewed_ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(
            span(ap,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in
            ((0x1870418,0x187042c),(0x18727dc,0x18728b4),*getter_ranges)],
        fragments_executed_separately=True,locking_helpers_executed=False,
        ff_restriction_evaluated=False,restriction_marker_semantics_verified=False,
        runtime_settings_verified=False,uncropped_readout_verified=False,
        camera_io=False,firmware_file_written=False,movie_path_verified=False,
        recording_verified=False,installable=False)
