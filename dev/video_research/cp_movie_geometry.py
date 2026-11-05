"""Conditional normal movie geometry DAG, without scheduler/ISP execution."""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span


def inspect(cp:bytes)->dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    ranges=((0x4d7f12,0x4d7f1c),(0x4d89e2,0x4d89f4),(0x4d977a,0x4d97a8),
        (0x4d5be2,0x4d5c00),(0x4d5c4e,0x4d5c88),(0x4d5d94,0x4d5e2a),
        (0xb2c21a,0xb2c25e),(0x4c8dfe,0x4c8e7e),(0xb28c16,0xb28c54),
        (0xb2b57c,0xb2b5d6),(0x4c96b0,0x4c96da),(0x4c9810,0x4c98a4),
        (0xb2a980,0xb2a9be),(0xb2aa6e,0xb2aa90),(0x4c0328,0x4c033e),(0x4c0c30,0x4c0c48),(0xb29e9a,0xb29ea8),(0xb29f60,0xb29f68),(0xb2a3c4,0xb2a3ce),
        (0x4e5bb2,0x4e5bf8),(0x4e6080,0x4e6112),(0x4e5e8a,0x4e5ea4),(0x5475b0,0x547610),
        (0x54128c,0x54141a),(0xba893a,0xba8970),(0xba8d82,0xba8daa),(0xba94be,0xba94e4),
        (0xe9c76c,0xe9c7e0))
    calculation_targets=[struct.unpack('<I',cp_span(cp,table+0x28,4))[0] for table in (0xe9c774,0xe9c7b4)]
    if calculation_targets!=[0x544d9d,0x5459ed]:raise ValueError('Distortion calculation virtual targets differ')
    diagnostic=cp_span(cp,0x547674,64).split(b'\0')[0].decode('ascii')
    if diagnostic!='rcct_DistCorrectionCalcMulti':raise ValueError('Calculation diagnostic differs')
    return dict(schema='a7c2-cp-movie-geometry-static/1',cp_sha256=CP_SHA,
        coordinate_identity='ROOT+11d8 = pending request(ROOT+1144)+94 = selector(ROOT+e18)+3c0',
        format_projection='4d7f16/18 copies snapshot+28; previously verified 304-byte copies1144->1448->e38 preserve +94',
        geometry='4d4298: record+1c==0 admits record+94 format branch; format3 reads original3840x2160 pair global1a53130+98',
        per_stream_producer='4d97a4 -> 4d5bd4 output ROOT+189c=(instance+c)+a84; record+1c must0, otherwise valid byte cleared and return',
        producer_details='4d5c58..86 copies (instance+c)+a7c/a7e to four stream+0c/+0e pairs. 4d5d94..e0c allows only nonzero dimension reductions on streams1..3. 4d5e0c..2a aligns +08 to64 units and copies height to+0a.',
        producer_remaining='4d5e2a onward merges equivalent descriptors and derives policies; not executed here',
        stream_handoff='4c7d7e -> b2c1b8; b2c21a..25e copies four stride18 sources into receiver stride70: +08/+0a -> +1b4/+1b6, +0c/+0e -> +1b8/+1ba, +10/+12 -> +1bc/+1be, +14 -> +1c0',
        queued_isp=dict(enqueue='4c8e0a receiver fp -> r2, wrapper b2b4ad, callback b2b57d; 4c8e7a -> b28c16 -> b294e2',
            receiver='same payload+14 -> node+1c -> b29366 wrapper b2b4ac -> callback r0, conditional scheduler dispatch',
            gates='b2b582 helper must1; receiver+1514==0 for b2b5bc ->4c96b0; b2fddc must1 and real OS wait succeeds',
            alternate='receiver+1514!=0 can enqueue b2b717 through b28c5c, with its own helper gate; not executed'),
        isp_argument='4c9820 computes receiver+1b8; 4c9882 passes pointer as first stack argument to4e59e0 at4c98a0',
        descriptor='4e5bbe/5bc0 forwards that pointer as second stack argument to4e6000 at4e5bf4. 4e6088 loads it into r4; when source block+80==0,4e60ce..f2 rounds width to64 units into descriptor+c0 and copies height into+c2.',
        lowres_lookup_flag_provenance='On reviewed4c0c44 route: b2a93a reads snapshot+d08/d09, or global1a533a4+1 override1..4. Normalized d08 travels r3->4c0328.r8->b29e9a.r2->record+5; d09 travels first stack arg->4c0328.[r7+8]->b29e9a.r3->record+6. No semantic names assigned.',
        lower_consumer_subsystem=dict(diagnostic=diagnostic,source_names=['api_rc.cpp','RcDriver.cpp'],
            call_chain='4e5ea0 ->5475b0 ->54128c; distortion-correction calculation, not established image-buffer handoff',
            static_singletons=[dict(object='0x1a7a61c',constructor='0xba8948',vtable='0xe9c774',slot_28_target=hex(calculation_targets[0])),
                dict(object='0x1a7a620',constructor='0xba8d82',vtable='0xe9c7b4',slot_28_target=hex(calculation_targets[1]))],
            runtime_registry='ba8da0 ->1a7a624; ba94be walks +4 list, matches object+90 handle; ba4e8c reads object+2c+4*index',
            runtime_command_object='54139e calls selected stream vtable+8; result+8 and+1dc feed calculation slot28 at5413e8',
            runtime_registry_contents_verified=False,command_object_is_encoded_frame_buffer_verified=False),
        exact_missing_edges=['callback readiness/allocation/scheduling and current configuration',
            'physical coverage and cadence of candidate sensor readout',
            'source/output geometry and pixel-format compatibility of ISP transforms',
            'which produced buffer reaches verified MPR UHD200Mbps encoder target'],
        scaler_capability_verified=False,alignment_unit_bytes_verified=False,
        isp_execution_verified=False,encoder_buffer_identity_verified=False,
        safe_patch_location_established=False,camera_io=False,installable=False,
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest()) for lo,hi in ranges])


def run_original(cp:bytes)->dict:
    """Original per-stream align/copy and descriptor tail, separately executed."""
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
    for page in (0x4d5000,0xb2c000,0x4e6000):
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,4096))
    base=0x21000000;source=base+0x100;receiver=base+0x1000;desc=base+0x2000;frame=base+0x2800
    uc.mem_map(base,0x3000,u.UC_PROT_READ|u.UC_PROT_WRITE)
    initial=bytearray(b'\xa5'*0x3000)
    for i,(w,h) in enumerate(((3840,2160),(1920,1080),(1280,720),(640,480))):
        struct.pack_into('<I',initial,0x100+4+i*0x18,i+1)
        struct.pack_into('<6H',initial,0x100+8+i*0x18,0,0,w,h,0,0)
        struct.pack_into('<I',initial,0x100+0x14+i*0x18,0x1230+i)
        initial[0x100+0x18+i*0x18]=i
    struct.pack_into('<I',initial,0x2800+0x24,0x2345)
    uc.mem_write(base,bytes(initial));trace=[];end=[0];done=[]
    ranges=((0x4d5e0c,0x4d5e2a),(0xb2c21a,0xb2c25e),(0x4e60ce,0x4e60f6))
    def code(em,pc,size,_):
        if pc==end[0]:done.append(pc);em.emu_stop();return
        if not any(lo<=pc and pc+size<=hi for lo,hi in ranges):raise ValueError('Unreviewed movie geometry instruction')
        if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Movie geometry left Thumb')
        trace.append((pc,size))
    writes=[(source+8+i*0x18,source+12+i*0x18) for i in range(4)]
    writes += [(receiver+0x1b0+i*0x70,receiver+0x1c5+i*0x70) for i in range(4)]
    writes += [(frame-0x24,frame-0x1c),(desc+0xc0,desc+0xc8)]
    def memory(em,access,addr,size,value,_):
        if access==u.UC_MEM_WRITE:
            if not any(lo<=addr and addr+size<=hi for lo,hi in writes):raise ValueError('Unexpected movie geometry write')
        elif not (source<=addr and addr+size<=source+0x80 or receiver+0x1b8<=addr and addr+size<=receiver+0x1bc or frame+0x18<=addr and addr+size<=frame+0x28):raise ValueError('Unexpected movie geometry read')
    uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
    def run(start,stop,regs):
        for reg,val in regs:uc.reg_write(reg,val)
        end[0]=stop;uc.emu_start(start|1,0,count=200,timeout=1_000_000)
        if done[-1:]!=[stop]:raise ValueError('Movie geometry boundary not reached')
    run(0x4d5e0c,0x4d5e2a,((a.UC_ARM_REG_R4,source),(a.UC_ARM_REG_SP,frame-0x40),(a.UC_ARM_REG_R5,0),(a.UC_ARM_REG_R12,0)))
    run(0xb2c21a,0xb2c25e,((a.UC_ARM_REG_R6,source),(a.UC_ARM_REG_R9,receiver)))
    rows=[]
    for i in range(4):
        data=bytes(uc.mem_read(receiver+0x1b0+i*0x70,0x15));src=bytes(uc.mem_read(source+4+i*0x18,0x15))
        if data!=src:raise ValueError('Per-stream descriptor copy differs')
        rows.append(list(struct.unpack('<4H',data[4:12])))
    run(0x4e60ce,0x4e60f6,((a.UC_ARM_REG_R4,receiver+0x1b8),(a.UC_ARM_REG_R7,frame),(a.UC_ARM_REG_R11,desc),(a.UC_ARM_REG_R8,0)))
    result=list(struct.unpack('<4H',uc.mem_read(desc+0xc0,8)))
    if result!=[3840,2160,0x2345,0]:raise ValueError('ISP descriptor geometry differs')
    actual=bytes(uc.mem_read(base,0x3000))
    for i,(before,after) in enumerate(zip(initial,actual)):
        if before!=after and not any(lo<=base+i<hi for lo,hi in writes):raise ValueError('Movie geometry canary differs')
    return dict(schema='a7c2-cp-movie-geometry-original/1',cp_sha256=CP_SHA,
        declared_stream_dimensions=[[3840,2160],[1920,1080],[1280,720],[640,480]],
        copied_fields_1b4_to_1ba=rows,descriptor_c0_to_c6=result,
        instructions=len(trace),instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest(),
        fragments_executed_separately=True,producer_overrides_or_merging_executed=False,
        descriptor_branch_precondition_executed=False,isp_calls_executed=False,
        encoder_handoff_verified=False,camera_io=False,installable=False)
