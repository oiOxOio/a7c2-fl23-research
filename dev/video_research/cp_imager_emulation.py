"""Two separately executed CP handler fragments; never a full message dispatch.

The gap contains unreviewed helper calls. Stage two is initialized separately,
not represented as a continuation across those helpers. No success stubs.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,BASE,check_image,cp_span

CONTEXT=0x165a720
INSTANCE=0x173efe8
TRACE=0x1a533a4
GETTER=(0xb2ddb4,0xb2ddbe)


def run_original(cp: bytes, *, message_id: int = 0x40a3) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    if type(message_id) is not int or message_id not in (0x40a2,0x40a3):
        raise ValueError('Unreviewed imager message.')
    request_range, derived_range, request_field = (
        ((0x358754,0x35879e),(0x3587a2,0x3587e8),0x2a0) if message_id==0x40a3 else
        ((0x35858c,0x3585d6),(0x3585da,0x358620),0x29c))
    import unicorn as u
    from unicorn import arm_const as a
    row=0x10fb76c if message_id==0x40a3 else 0x10fb758
    row_bytes=cp_span(cp,row,20)
    row_words=struct.unpack('<IIIII',row_bytes)
    if row_words[0]!=message_id or row_words[1]!=request_range[0]+1:
        raise ValueError('Original dispatcher row differs.')
    cases=[]
    for phase in ('request_store','derived_flag'):
        vectors=([(gate,value,0,0) for gate in (0,1) for value in (0,1,2,255)]
                 if phase=='request_store' else
                 [(gate,value,mode,policy) for gate in (0,1) for value in (0,1,2)
                  for mode in (0,0x1f,0x20) for policy in (0,1,2)])
        start,stop=request_range if phase=='request_store' else derived_range
        for gate,value,mode,policy in vectors:
            uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
            for page in {start & ~4095, GETTER[0] & ~4095}:
                uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
                uc.mem_write(page,cp_span(cp,page,4096))
            stack,request,object2=0x20000000,0x21000000,0x22000000
            for addr in (stack,request,object2,CONTEXT & ~4095,INSTANCE & ~4095,TRACE & ~4095):
                uc.mem_map(addr,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.mem_write(stack,b'\xa5'*4096)
            uc.mem_write(request+8,bytes([value]))
            uc.mem_write(INSTANCE+12,struct.pack('<I',object2))
            uc.mem_write(object2+0x950,struct.pack('<I',gate))
            uc.mem_write(CONTEXT+0x138,struct.pack('<I',mode))
            uc.mem_write(CONTEXT+0x29c,struct.pack('<I',policy))
            uc.mem_write(CONTEXT+0x2a0,struct.pack('<I',value if phase=='derived_flag' else 0xcccccccc))
            uc.mem_write(CONTEXT+0x2a4,b'\xcc')
            uc.mem_write(TRACE+0x32,b'\0') # Explicit synthetic logging-disabled state.
            for addr in (request,object2,INSTANCE & ~4095,TRACE & ~4095):
                uc.mem_protect(addr,4096,u.UC_PROT_READ)
            sp=stack+0x800
            uc.reg_write(a.UC_ARM_REG_SP,sp)
            uc.reg_write(a.UC_ARM_REG_R0,request)
            uc.reg_write(a.UC_ARM_REG_R4,CONTEXT)
            uc.reg_write(a.UC_ARM_REG_LR,0x23000001)
            outcomes=[];writes=[];count=[0]
            def inst(em,address,size,unused):
                count[0]+=1
                if count[0]>100: raise ValueError('CP instruction limit.')
                if address==stop:outcomes.append(address);em.emu_stop();return
                if not (start<=address<stop or GETTER[0]<=address<GETTER[1]):
                    raise ValueError('Unreviewed CP instruction.')
            def memory(em,access,address,size,value_written,unused):
                if access==u.UC_MEM_WRITE:
                    allowed=(sp-16<=address<=sp-size) if phase=='request_store' else False
                    field=CONTEXT+(request_field if phase=='request_store' else 0x2a4)
                    width=4 if phase=='request_store' else 1
                    allowed |= address==field and size==width
                    if not allowed:raise ValueError('Unexpected CP write.')
                    writes.append((address,size,value_written))
                else:
                    ranges=((sp-16,16),(request+8,1),(INSTANCE+12,4),
                            (object2+0x950,4),(CONTEXT+0x138,4),
                            (CONTEXT+0x29c,9),(TRACE+0x32,1))
                    if not any(base<=address and address+size<=base+n for base,n in ranges):
                        raise ValueError('Unexpected CP read.')
            uc.hook_add(u.UC_HOOK_CODE,inst)
            uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(start|1,0,count=101,timeout=1_000_000)
            if outcomes != [stop]:raise ValueError('Unexpected CP stop.')
            frame = 16 if phase == 'request_store' else 0
            if uc.reg_read(a.UC_ARM_REG_SP) != sp-frame:
                raise ValueError('Unexpected CP stack adjustment.')
            if bytes(uc.mem_read(stack,sp-frame-stack)) != b'\xa5'*(sp-frame-stack):
                raise ValueError('Lower stack canary changed.')
            if bytes(uc.mem_read(sp,stack+4096-sp)) != b'\xa5'*(stack+4096-sp):
                raise ValueError('Upper stack canary changed.')
            if phase=='request_store':
                expected=value if gate==0 else 0
                actual=struct.unpack('<I',bytes(uc.mem_read(CONTEXT+request_field,4)))[0]
                field=request_field
            else:
                expected=(2 if mode==0x20 else (1 if gate==0 else 2) if mode==0x1f
                          else 1 if policy==2 else int(value==1) if policy==1 else 0)
                actual=uc.mem_read(CONTEXT+0x2a4,1)[0];field=0x2a4
            if actual != expected:raise ValueError('CP fragment result mismatch.')
            cases.append(dict(phase=phase,gate_950=gate,request_or_state_value=value,
                mode_138=mode,policy_29c=policy,result_field=hex(field),result=actual,
                stopped_before=hex(stop),instructions=count[0]-1))
    return dict(schema='a7c2-cp-imager-fragments/1',cp_sha256=CP_SHA,message_id=hex(message_id),
        static_dispatch_row=dict(va=hex(row),handler=hex(row_words[1]),check_callback=hex(row_words[4]),
            sha256=hashlib.sha256(row_bytes).hexdigest(),runtime_dispatch_verified=False),
        reviewed_ranges=[dict(start=hex(s),end=hex(e),sha256=hashlib.sha256(cp_span(cp,s,e-s)).hexdigest())
            for s,e in (request_range,derived_range,GETTER)],
        cases=cases,case_count=len(cases),synthetic_context=True,
        fragments_executed_separately=True,unknown_helpers_executed=0,
        camera_io=False,firmware_file_written=False,dispatcher_executed=False,
        message_delivery_verified=False,movie_path_verified=False,
        recording_verified=False,installable=False)
