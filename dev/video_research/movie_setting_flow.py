"""Pinned movie setting → wire-format fragments; never a recording/unlock test.

Each fragment has declared synthetic entry state and stops before unknown helpers.
The CP validity table is not identified as an uncropped/full-frame capability table.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE,AP_SHA,CP_SIZE,CP_SHA,Elf64,check_image,span,cp_span


def inspect(ap: bytes,cp: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');check_image(cp,CP_SIZE,CP_SHA,'CP');elf=Elf64(ap)
    ap_ranges=((0x3106e40,0x3106e58),(0x3106ea0,0x3106eb8),
        (0x31bc01c,0x31bc028),(0x31bc0f0,0x31bc110),(0x344ffc8,0x3450090),
        (0x3451628,0x345168c),(0x34517e0,0x3451828),(0x34518b8,0x34518c0),
        (0x3545ab8,0x3545b64),(0x3545cec,0x3545cf4),(0x3545d6c,0x3545d74))
    return dict(schema='a7c2-movie-setting-static/1',ap_sha256=AP_SHA,cp_sha256=CP_SHA,
        message_id='0x4000',movie_diagnostic='0x4c7e8b8',sequence_typeinfo='0x4c53fb0',
        model_fields={'0x24':'getter 0x286608c through 0x3106e40',
            '0x40':'getter 0x286612c through 0x3106ea0; value 8 substitutes companion getter'},
        ordinary_path=dict(format_value=7,rate_value=0,rate_override_conditions_bypassed=True,
            builder_format=4,builder_rate=20,wire_format_byte8=3,wire_rate_byte9=0,wire_flag_byte10=0),
        diagnostic_parameter_binding=dict(success_string='0xf7b2ac',failure_string='0xf7b24c',
            fields={'0x8':'size','0x9':'sysfr','0xa':'ilmode','0xc':'sqfr',
                    '0x10':'asp','0x11':'raw','0x12':'yuvbit'},
            success_arguments='0x35439e..0x3543aa; r1/r2/r3 and four stack words',
            raw_argument_origin='0x354310 loads ip from message +0x11; success logger stack +8',
            numeric_enum_names_verified=False,
            strings_sha256=[hashlib.sha256(cp_span(cp,addr,96).split(b'\0',1)[0]).hexdigest()
                            for addr in (0xf7b24c,0xf7b2ac)]),
        cp_dispatch=dict(row='0x10fab8c',handler='0x35421d',runtime_dispatch_verified=False),
        cp_format_rate_table=dict(va='0xf812dc',rows=13,columns=7,cell_3_0=cp_span(cp,0xf812dc+21,1)[0],
            sha256=hashlib.sha256(cp_span(cp,0xf812dc,91)).hexdigest(),
            uncropped_capability_semantics_verified=False),
        ap_ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(
            span(ap,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ap_ranges],
        cp_ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((0x35421c,0x354268),(0x3542f0,0x354334),(0x35438a,0x35438e),(0x354334,0x354352),(0x35439e,0x3543bc))],
        condition='Numeric 7/0 association to XAVC S 4K 60P originates in caution descriptors; this adds actual setting-field dataflow, not a physical capture proof.',
        unresolved=['alternative rate overrides and value-8 substitution at runtime',
            'sequence scheduling and transport delivery','joint dependency with APS-C policy and sensor selector',
            'full-frame 4K60 readout and encoded bitrate'],
        continuous_end_to_end_execution_verified=False,camera_io=False,recording_verified=False,installable=False)


def run_ap_original(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    cases=[]
    # Sequence fragment executes the real get_setting_movie_rec_frame_rate function.
    for rate,expected_rate in ((0,20),(1,18),(2,15)):
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for page in (0x3451000,0x344f000,0x3450000,0x4c53000):
            uc.mem_map(page,4096,u.UC_PROT_READ|(0 if page==0x4c53000 else u.UC_PROT_EXEC))
            uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
        stack,obj,fp=0x10000000,0x20000000,0x10000800
        uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(stack,b'\xa5'*4096)
        uc.mem_map(obj,4096,u.UC_PROT_READ)
        uc.mem_write(obj+0x14,struct.pack('<I',0x12345678));uc.mem_write(obj+0x24,struct.pack('<I',7))
        uc.mem_write(obj+0x40,struct.pack('<I',rate))
        # Model override fields explicitly zero: this is one ordinary conditional path.
        for off in (0x588,0x43c,0x450):uc.mem_write(obj+off,struct.pack('<I',0))
        for reg,value in ((a.UC_ARM64_REG_X19,obj),(a.UC_ARM64_REG_X29,fp),(a.UC_ARM64_REG_SP,fp)):
            uc.reg_write(reg,value)
        path=[];stopped=[]
        def instruction(em,addr,size,_):
            if addr==0x34518c0:stopped.append(addr);em.emu_stop();return
            ranges=((0x3451628,0x345168c),(0x34517e0,0x3451828),(0x34518b8,0x34518c0),
                (0x3451970,0x34519a8),(0x344ffc8,0x3450048),(0x3450060,0x3450090),(0x34503b4,0x34503cc))
            if size!=4 or not any(lo<=addr<hi for lo,hi in ranges):raise ValueError('Unreviewed movie sequence instruction.')
            path.append(addr)
        def memory(em,access,addr,size,value,_):
            allowed=fp-64<=addr and addr+size<=fp+0x11c
            if access==u.UC_MEM_READ:
                allowed |= any(lo<=addr and addr+size<=lo+n for lo,n in
                    ((obj+0x14,4),(obj+0x24,4),(obj+0x40,4),(obj+0x588,4),(obj+0x43c,4),(obj+0x450,4),
                     (0x4c53c1c,8),(0x4c53c98,8),(0x4c53ca0,8)))
            if not allowed:raise ValueError('Unexpected movie sequence memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x3451628,0,count=200,timeout=1_000_000)
        result=struct.unpack('<IIII',bytes(uc.mem_read(fp+0xb8,16)))
        if stopped!=[0x34518c0] or result!=(0x12345678,4,2,expected_rate):raise ValueError('Movie sequence conversion mismatch.')
        for lo,hi in ((stack,fp-64),(fp+0x11c,stack+4096)):
            if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Movie sequence canary changed.')
        cases.append(dict(phase='sequence',format=7,rate=rate,builder_format=4,builder_rate=expected_rate,
            stopped_before='0x34518c0',instruction_stream_sha256=hashlib.sha256(b''.join(
                span(ap,elf.file_offset(x,4),4) for x in path)).hexdigest()))
    # Independent builder prefixes; no message submission.
    for builder_rate,wire_rate in ((20,0),(18,1),(15,4)):
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for page in (0x3545000,0x4c7d000):
            uc.mem_map(page,4096,u.UC_PROT_READ|(u.UC_PROT_EXEC if page==0x3545000 else 0))
            uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
        stack,inp,sp=0x10000000,0x20000000,0x10000800
        uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(stack,b'\xa5'*4096)
        uc.mem_map(inp,4096,u.UC_PROT_READ);uc.mem_write(inp,struct.pack('<IIII',0x12345678,4,2,builder_rate))
        uc.reg_write(a.UC_ARM64_REG_SP,sp);uc.reg_write(a.UC_ARM64_REG_X0,inp);uc.reg_write(a.UC_ARM64_REG_X1,0x21000000)
        path=[];stopped=[]
        def instruction(em,addr,size,_):
            if addr==0x3545d74:stopped.append(addr);em.emu_stop();return
            ranges=((0x3545ab8,0x3545b54),(0x3545cec,0x3545cf4),(0x3545d6c,0x3545d74),(0x3545e18,0x3545e24),(0x3545e40,0x3545e48))
            if size!=4 or not any(lo<=addr<hi for lo,hi in ranges):raise ValueError('Unreviewed movie builder instruction.')
            path.append(addr)
        def memory(em,access,addr,size,value,_):
            allowed=sp-0x70<=addr and addr+size<=sp
            if access==u.UC_MEM_READ:allowed |= any(lo<=addr and addr+size<=lo+n for lo,n in
                ((inp,16),(0x4c7d368,8),(0x4c7d370,30)))
            if not allowed:raise ValueError('Unexpected movie builder memory access.')
        uc.hook_add(u.UC_HOOK_CODE,instruction);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x3545ab8,0,count=100,timeout=1_000_000)
        payload=bytes(uc.mem_read(sp-0x18,20))
        if stopped!=[0x3545d74] or payload[:11]!=struct.pack('<BBHI3B',5,0,0x4000,0x12345678,3,wire_rate,0):
            raise ValueError('Movie wire prefix differs.')
        if uc.reg_read(a.UC_ARM64_REG_SP)!=sp-0x70:raise ValueError('Movie builder stack differs.')
        for lo,hi in ((stack,sp-0x70),(sp,stack+4096)):
            if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('Movie builder canary changed.')
        cases.append(dict(phase='builder',builder_rate=builder_rate,message_id='0x4000',wire_bytes_8_9_10=[3,wire_rate,0],
            stopped_before='0x3545d74',remaining_payload_unverified=True,instruction_stream_sha256=hashlib.sha256(
                b''.join(span(ap,elf.file_offset(x,4),4) for x in path)).hexdigest()))
    return dict(schema='a7c2-movie-ap-fragments/1',ap_sha256=AP_SHA,cases=cases,
        synthetic_inputs=True,fragments_executed_separately=True,unknown_helpers_executed=0,
        message_submitted=False,camera_io=False,recording_verified=False,installable=False)


def run_cp_original(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for phase in ('rate_normalization','format_rate_validation'):
        vectors=((0,0),(0,1),(4,0)) if phase=='rate_normalization' else ((0,0),(0,2),(1,0),(1,2))
        for normalized_or_rate,flag in vectors:
            uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
            uc.mem_map(0x354000,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            uc.mem_write(0x354000,cp_span(cp,0x354000,4096))
            uc.mem_map(0xf81000,4096,u.UC_PROT_READ);uc.mem_write(0xf81000,cp_span(cp,0xf81000,4096))
            stack,req,sp=0x20000000,0x21000000,0x20000800
            uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(stack,b'\xa5'*4096)
            uc.mem_map(req,4096,u.UC_PROT_READ)
            uc.mem_write(req+9,bytes([normalized_or_rate,flag]))
            uc.mem_write(req+17,bytes([flag]))
            for reg,value in ((a.UC_ARM_REG_SP,sp),(a.UC_ARM_REG_R0,req),(a.UC_ARM_REG_R6,req),
                              (a.UC_ARM_REG_R4,req+17),(a.UC_ARM_REG_R1,3),(a.UC_ARM_REG_R5,normalized_or_rate)):
                uc.reg_write(reg,value)
            start=0x35421c if phase=='rate_normalization' else 0x3542f0
            stops=(0x354268,) if phase=='rate_normalization' else (0x354334,0x35438e)
            stopped=[];path=[]
            def instruction(em,addr,size,_):
                if addr in stops:stopped.append(addr);em.emu_stop();return
                ranges=((0x35421c,0x354234),(0x35423e,0x354254),(0x354266,0x354268)) if phase=='rate_normalization' else (
                    (0x3542f0,0x354334),(0x35438a,0x35438e))
                if not any(lo<=addr and addr+size<=hi for lo,hi in ranges):raise ValueError('Unreviewed CP movie instruction.')
                path.append((addr,size))
            def memory(em,access,addr,size,value,_):
                if access==u.UC_MEM_WRITE:
                    allowed=phase=='rate_normalization' and sp-56<=addr and addr+size<=sp
                else:
                    allowed=any(lo<=addr and addr+size<=lo+n for lo,n in
                        ((req+9,2),(req+17,1),(0x354234,10),(0xf812dc,91)))
                if not allowed:raise ValueError('Unexpected CP movie memory access.')
            uc.hook_add(u.UC_HOOK_CODE,instruction);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(start|1,0,count=100,timeout=1_000_000)
            expected_stop=0x354268 if phase=='rate_normalization' else 0x35438e if normalized_or_rate==0 else 0x354334
            if stopped!=[expected_stop]:raise ValueError('Unexpected CP movie boundary.')
            if phase=='rate_normalization' and uc.reg_read(a.UC_ARM_REG_R5)!=(2 if normalized_or_rate==4 else flag):
                raise ValueError('Unexpected CP normalized rate.')
            frame=56 if phase=='rate_normalization' else 0
            for lo,hi in ((stack,sp-frame),(sp,stack+4096)):
                if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('CP movie stack canary changed.')
            cases.append(dict(phase=phase,wire_or_normalized_rate=normalized_or_rate,synthetic_flag=flag,
                normalized_rate=uc.reg_read(a.UC_ARM_REG_R5),stopped_before=hex(expected_stop),
                selected_accept_path=phase=='format_rate_validation' and expected_stop==0x35438e,
                instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in path)).hexdigest()))
    return dict(schema='a7c2-movie-cp-fragments/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_inputs=True,fragments_executed_separately=True,unknown_helpers_executed=0,
        state_writes_executed=False,uncropped_capability_verified=False,
        camera_io=False,recording_verified=False,installable=False)
