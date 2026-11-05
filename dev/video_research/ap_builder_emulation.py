"""Execute a reviewed original AP message-builder prefix, stopping BEFORE calls.

No imports, syscalls, device access, helper stubs, complete function execution or
submission occur. Inputs are synthetic; the diagnostic string is only a lead.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE,AP_SHA,Elf64,check_image

START=0x353deb8
STOP=0x353df14
REJECT=0x353df50


def run_original(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP')
    elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    page=START & ~4095
    code=ap[elf.file_offset(page,4096):elf.file_offset(page,4096)+4096]
    cases=[]
    for ident in (0,1,0x12345678,0xffffffff):
        for setting in (0,1,2,0xffffffff):
            uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
            uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            uc.mem_write(page,code)
            stack,inp,out=0x10000000,0x20000000,0x20001000
            uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.mem_write(stack,b'\xa5'*4096)
            uc.mem_map(inp,4096,u.UC_PROT_READ)
            uc.mem_write(inp,struct.pack('<III',ident,0xaabbccdd,setting))
            # Deliberately do NOT map the output pointer; the prefix may not write it.
            sp=stack+0x800
            uc.reg_write(a.UC_ARM64_REG_SP,sp)
            uc.reg_write(a.UC_ARM64_REG_X0,inp)
            uc.reg_write(a.UC_ARM64_REG_X1,out)
            outcome=[];count=[0]
            def instruction(em,address,size,unused):
                count[0]+=1
                if count[0]>100:
                    raise ValueError('Instruction limit exceeded.')
                if address in (STOP,REJECT):
                    outcome.append(address);em.emu_stop();return
                if size != 4 or not START<=address<STOP:
                    raise ValueError('Unreviewed AP instruction; no execution allowed.')
            def memory(em,access,address,size,value,unused):
                if access==u.UC_MEM_WRITE and not sp-0x50<=address<=sp-size:
                    raise ValueError('Write outside declared stack frame.')
                if access==u.UC_MEM_READ and not (
                    sp-0x50<=address<=sp-size or inp<=address<=inp+12-size):
                    raise ValueError('Read outside input/stack.')
            uc.hook_add(u.UC_HOOK_CODE,instruction)
            uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(START,0,count=101,timeout=1_000_000)
            expected_stop=STOP if setting in (0,1) else REJECT
            if outcome != [expected_stop]: raise ValueError('Unexpected stop condition.')
            actual_sp=uc.reg_read(a.UC_ARM64_REG_SP)
            if actual_sp != sp-0x50: raise ValueError('Unexpected prefix stack adjustment.')
            if bytes(uc.mem_read(stack,sp-0x50-stack)) != b'\xa5'*(sp-0x50-stack):
                raise ValueError('Lower stack canary changed.')
            if bytes(uc.mem_read(sp,stack+4096-sp)) != b'\xa5'*(stack+4096-sp):
                raise ValueError('Upper stack canary changed.')
            payload=bytes(uc.mem_read(actual_sp+0x40,12))
            expected=struct.pack('<BBHII',5,0,0x40a3,ident,setting if setting in (0,1) else 0)
            if payload != expected: raise ValueError('Unexpected pre-helper message bytes.')
            if setting in (0,1):
                if (uc.reg_read(a.UC_ARM64_REG_X0),uc.reg_read(a.UC_ARM64_REG_X1),uc.reg_read(a.UC_ARM64_REG_X2)) != (0x40a3,actual_sp+0x48,4):
                    raise ValueError('Unexpected first-helper arguments.')
            cases.append(dict(input_word0=hex(ident),input_word8=hex(setting),
                stopped_before=hex(expected_stop),instructions=count[0]-1,
                payload_header_u8=payload[0],message_id_u16=hex(0x40a3),
                payload_word4=hex(ident),payload_word8=hex(struct.unpack_from('<I',payload,8)[0]),
                helper_executed=False))
    return dict(schema='a7c2-ap-builder-prefix/1',ap_sha256=AP_SHA,
        prefix_va=hex(START),prefix_end_exclusive=hex(STOP),
        prefix_sha256=hashlib.sha256(ap[elf.file_offset(START,STOP-START):elf.file_offset(START,STOP-START)+STOP-START]).hexdigest(),
        cases=cases,case_count=len(cases),synthetic_inputs=True,
        helper_calls_executed=0,camera_io=False,firmware_file_written=False,
        full_function_executed=False,message_submitted=False,
        movie_path_verified=False,recording_verified=False,installable=False)
