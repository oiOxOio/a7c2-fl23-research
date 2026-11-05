"""Run original 0x40a3 check callback; stop before any diagnostic helper.

Synthetic mutable state is explicit. Returning is not proof of delivery/recording;
a diagnostic call boundary is not assigned an unverified success/failure meaning.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span

START=0x3626b8
CONTEXT=0x165a720
INSTANCE=0x173efe8
RANGES=((START,0x362742),(0x8db1b8,0x8db1c2),(0xb2ddb4,0xb2ddbe),(0x8daa5a,0x8daa9c))


def run_original(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    # state,gate,request,current,mode,policy,derived,expected stop
    vectors=((0,0,1,0,0,0,0,'returned'),
             (2,0,1,0,0,0,0,'returned'),
             (1,0,0,0,0,0,0,'returned'),
             (1,0,1,1,0,1,1,'returned'),
             (1,0,1,0,0,0,0,'diagnostic'),
             (1,1,1,0,0,0,0,'returned'),
             (1,1,1,1,0,0,0,'diagnostic'),
             (1,0,1,1,0x1f,0,1,'returned'),
             (1,1,1,0,0x1f,0,2,'returned'),
             (1,0,0,0,0x20,0,2,'returned'),
             (1,0,0,0,0x20,0,0,'diagnostic'))
    cases=[]
    for state,gate,request_value,current,mode,policy,derived,expected in vectors:
        uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        for lo,hi in RANGES:
            page=lo & ~4095
            uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            uc.mem_write(page,cp_span(cp,page,4096))
        stack,request,obj,returned=0x20000000,0x21000000,0x22000000,0x23000000
        for page in (stack,request,obj,CONTEXT & ~4095,INSTANCE & ~4095,returned):
            uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
        uc.mem_write(stack,b'\xa5'*4096)
        uc.mem_write(request+8,bytes([request_value]))
        for address,value in ((CONTEXT+0x138,mode),(CONTEXT+0x29c,policy),
            (CONTEXT+0x2a0,current),(INSTANCE+12,obj),(obj+0x950,gate)):
            uc.mem_write(address,struct.pack('<I',value))
        uc.mem_write(CONTEXT+0x2a4,bytes([derived]))
        for page in (request,obj,CONTEXT & ~4095,INSTANCE & ~4095):
            uc.mem_protect(page,4096,u.UC_PROT_READ)
        uc.mem_protect(returned,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        # A fetchable stop page only; no synthetic return instruction executes.
        uc.mem_map(0xb44000,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        sp=stack+0x800
        uc.reg_write(a.UC_ARM_REG_SP,sp)
        uc.reg_write(a.UC_ARM_REG_R0,request)
        uc.reg_write(a.UC_ARM_REG_R1,state)
        uc.reg_write(a.UC_ARM_REG_LR,returned|1)
        outcome=[];count=[0]
        def instruction(em,address,size,unused):
            count[0]+=1
            if address in (returned,0xb4457a):
                outcome.append('returned' if address==returned else 'diagnostic')
                em.emu_stop();return
            if not any(lo<=address and address+size<=hi for lo,hi in RANGES):
                raise ValueError('Unreviewed check instruction.')
        def memory(em,access,address,size,value,unused):
            ranges=((sp-32,32),) if access==u.UC_MEM_WRITE else (
                (sp-32,32),(request+8,1),(CONTEXT+0x138,4),
                (CONTEXT+0x29c,9),(INSTANCE+12,4),(obj+0x950,4))
            if not any(lo<=address and address+size<=lo+n for lo,n in ranges):
                raise ValueError('Unexpected check memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction)
        uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(START|1,0,count=200,timeout=1_000_000)
        if outcome != [expected]:raise ValueError('Unexpected check boundary.')
        if expected=='returned' and uc.reg_read(a.UC_ARM_REG_SP)!=sp:
            raise ValueError('Check stack not restored.')
        for lo,hi in ((stack,sp-32),(sp,stack+4096)):
            if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):
                raise ValueError('Check stack canary changed.')
        cases.append(dict(synthetic_check_state=state,gate_950=gate,request_value=request_value,
            current_2a0=current,mode_138=mode,policy_29c=policy,derived_2a4=derived,
            observed_boundary=expected,instructions=count[0]-1))
    return dict(schema='a7c2-cp-check-callback/1',cp_sha256=CP_SHA,cases=cases,
        case_count=len(cases),synthetic_context=True,
        reviewed_ranges=[dict(start=hex(lo),end=hex(hi),
            sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest()) for lo,hi in RANGES],
        diagnostics_executed=False,kernel_routing_verified=False,message_delivery_verified=False,
        context_writes=False,camera_io=False,firmware_file_written=False,
        movie_path_verified=False,recording_verified=False,installable=False)
