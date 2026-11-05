"""Actual APS-C policy request (0x40a2), distinct from size notification/0x40a3.

Original diagnostics name input types, not their numeric enum constants. No
transport, settings mutation, helper stubs or physical camera operations occur.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE,AP_SHA,Elf64,check_image,span
from ap_xrefs import relative_relocations,direct_calls


def inspect(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    ranges=(('sequence_constructor',0x3108ce4,0x3108d48),
            ('sequence_callback',0x3433c3c,0x3433c68),
            ('wrapper',0x34cbe88,0x34cbec8),
            ('request_builder',0x3545404,0x3545494),
            ('converter',0x3524abc,0x3524c0c),
            ('setting_getter',0x286743c,0x2867450),
            ('temporary_getter',0x2862440,0x2862454),
            ('setting_writer',0x2564918,0x25649ec),
            ('setting_wrapper',0x25649ec,0x2564a80),
            ('menu_candidate_callback',0x1c2472c,0x1c2476c))
    menu_record,values=0x5a181d0,0x59db2f8
    count=struct.unpack('<I',span(ap,elf.file_offset(menu_record+0x54,4),4))[0]
    ptr=struct.unpack('<Q',span(ap,elf.file_offset(menu_record+0x58,8),8))[0]
    if count!=3 or ptr!=values:raise ValueError('Menu value descriptor differs.')
    value_rows=[]
    for i in range(count):
        va=values+i*0xb8;raw=span(ap,elf.file_offset(va,0xb8),0xb8)
        value_rows.append(dict(va=hex(va),selected_id=hex(struct.unpack_from('<I',raw,4)[0]),
            converted_setting=struct.unpack_from('<I',raw,0x60)[0],sha256=hashlib.sha256(raw).hexdigest()))
    return dict(schema='a7c2-ap-apsc-policy-static/1',ap_sha256=AP_SHA,message_id='0x40a2',
        diagnostic_va='0x4c82ee8',input_types=['model::setting_super_35mm_t','model::apsc_full_frame_temporary_auto_t'],
        setting_getter='0x286743c',setting_state='0x7e6e620',temporary_getter='0x2862440',temporary_state='0x7e67740',
        constructor_fields={'0x14':'request identifier getter 0x352d794','0x18':'setting getter','0x1c':'temporary getter'},
        builder_inputs={'0x0':'identifier','0x4':'setting','0x8':'temporary'},
        vtable_callback_slot='0x5b3e620',vtable_typeinfo_name='0x4c4cb58',
        setting_store='0x256499c',setting_wrapper='0x25649ec',
        menu_candidate=dict(callback='0x1c2472c',relocation_slot='0x5a18258',
            selected_value_conversion='0x1b6eb2c',record=hex(menu_record),
            values=value_rows,selected_record_runtime_verified=False,
            runtime_menu_identity_verified=False),
        code_ranges=[dict(label=label,va=hex(lo),end_exclusive=hex(hi),file_offset=hex(elf.file_offset(lo,hi-lo)),
            sha256=hashlib.sha256(span(ap,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for label,lo,hi in ranges],
        callback_relocations=relative_relocations(elf,{0x3433c3c,0x1c2472c}),
        calls=direct_calls(elf,{0x3545404,0x34cbe88,0x25649ec}),
        full_apsc_enum_constants_verified=False,callback_scheduling_verified=False,
        end_to_end_delivery_verified=False,camera_io=False,recording_verified=False,installable=False)


def run_original(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    cases=[]
    for setting in (0,1,2,0xffffffff):
        for temporary in (0,1,2,0xffffffff):
            uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
            for page in (0x3545000,0x3524000):
                uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
                uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
            stack,inp,sp=0x10000000,0x20000000,0x10000800
            uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(stack,b'\xa5'*4096)
            uc.mem_map(inp,4096,u.UC_PROT_READ)
            uc.mem_write(inp,struct.pack('<III',0x12345678,setting,temporary))
            uc.reg_write(a.UC_ARM64_REG_SP,sp);uc.reg_write(a.UC_ARM64_REG_X0,inp)
            uc.reg_write(a.UC_ARM64_REG_X1,0x20001000) # Unmapped output pointer.
            stopped=[];path=[]
            def instruction(em,addr,size,_):
                if addr in (0x354545c,0x3524b08,0x3524bac):stopped.append(addr);em.emu_stop();return
                allowed=((0x3545404,0x354545c),(0x3524abc,0x3524b08),(0x3524ba0,0x3524bac))
                if size!=4 or not any(lo<=addr<hi for lo,hi in allowed):raise ValueError('Unreviewed APS-C instruction.')
                path.append(addr)
            def memory(em,access,addr,size,value,_):
                stack_ok=sp-0x70<=addr and addr+size<=sp
                input_ok=access==u.UC_MEM_READ and inp<=addr and addr+size<=inp+12
                if not (stack_ok or input_ok):raise ValueError('Unexpected APS-C memory access.')
            uc.hook_add(u.UC_HOOK_CODE,instruction);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(0x3545404,0,count=150,timeout=1_000_000)
            value=(2 if setting==0 else 0 if setting==2 else {0:1,1:2,2:0}.get(temporary)) if setting in (0,1,2) else None
            stop=0x354545c if value is not None else 0x3524b08 if setting==1 else 0x3524bac
            if stopped!=[stop]:raise ValueError('Unexpected APS-C boundary.')
            for lo,hi in ((stack,sp-0x70),(sp,stack+4096)):
                if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('APS-C stack canary changed.')
            payload=bytes(uc.mem_read(sp-16,12))
            if value is not None:
                if payload!=struct.pack('<BBHII',5,0,0x40a2,0x12345678,value):raise ValueError('APS-C payload mismatch.')
                if uc.reg_read(a.UC_ARM64_REG_SP)!=sp-0x40:raise ValueError('Converter stack not restored.')
            cases.append(dict(setting=hex(setting),temporary=hex(temporary),payload_byte8=value,
                stopped_before=hex(stop),instructions=len(path),
                instruction_stream_sha256=hashlib.sha256(b''.join(span(ap,elf.file_offset(x,4),4) for x in path)).hexdigest()))
    return dict(schema='a7c2-ap-apsc-builder/1',ap_sha256=AP_SHA,message_id='0x40a2',cases=cases,
        synthetic_inputs=True,original_converter_executed=True,unknown_helpers_executed=0,
        numeric_enum_names_verified=False,message_submitted=False,camera_io=False,
        recording_verified=False,installable=False)


def run_menu_values_original(ap: bytes) -> dict:
    """Execute lookup AFTER unresolved map selection, using declared original row.

The input node is synthetic. This verifies table fields/stride and conversion,
not which row the runtime map selects or a rendered menu label.
"""
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    record,values=0x5a181d0,0x59db2f8
    cases=[]
    for selected in (0x279,0x27a,0x27b,0x278,0x27c):
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for page in (0x1b6e000,record&~4095,values&~4095):
            uc.mem_map(page,4096,u.UC_PROT_READ|(u.UC_PROT_EXEC if page==0x1b6e000 else 0))
            uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
        node=0x10000000;uc.mem_map(node,4096,u.UC_PROT_READ);uc.mem_write(node,struct.pack('<Q',record))
        uc.reg_write(a.UC_ARM64_REG_X0,node);uc.reg_write(a.UC_ARM64_REG_W21,selected)
        stopped=[];path=[]
        def instruction(em,addr,size,_):
            if addr==0x1b6eb14:stopped.append(addr);em.emu_stop();return
            if size!=4 or not (0x1b6eadc<=addr<0x1b6eb14 or 0x1b6eb24<=addr<0x1b6eb2c):
                raise ValueError('Unreviewed menu conversion instruction.')
            path.append(addr)
        def memory(em,access,addr,size,value,_):
            ranges=((node,8),(record+0x54,4),(record+0x58,8),
                *((values+i*0xb8+off,4) for i in range(3) for off in (4,0x60)))
            if access!=u.UC_MEM_READ or not any(addr==lo and size==n for lo,n in ranges):
                raise ValueError('Unexpected menu conversion memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x1b6eadc,0,count=100,timeout=1_000_000)
        result=uc.reg_read(a.UC_ARM64_REG_W0)
        expected=selected-0x279 if 0x279<=selected<=0x27b else 0xffffffff
        if stopped!=[0x1b6eb14] or result!=expected:raise ValueError('Unexpected menu conversion result.')
        cases.append(dict(selected_id=hex(selected),setting_result=hex(result),
            instruction_stream_sha256=hashlib.sha256(b''.join(span(ap,elf.file_offset(x,4),4) for x in path)).hexdigest()))
    return dict(schema='a7c2-ap-apsc-menu-value-fragment/1',ap_sha256=AP_SHA,cases=cases,
        declared_record=hex(record),synthetic_selected_node=True,
        unresolved_map_selection_executed=False,runtime_record_selection_verified=False,
        display_label_semantics_verified=False,setting_written=False,camera_io=False,installable=False)
