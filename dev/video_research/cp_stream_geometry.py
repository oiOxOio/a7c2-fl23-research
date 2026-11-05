"""Original staged geometry branches; no ISP execution or recording claim."""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE, CP_SHA, check_image, cp_span


def inspect(cp: bytes) -> dict:
    check_image(cp, CP_SIZE, CP_SHA, 'CP')
    ranges=((0x4b752e,0x4b75cc),(0xb2a482,0xb2a548),(0x4d42f8,0x4d4464),
            (0x4d4554,0x4d4676),(0xb2c36c,0xb2c404),(0xb2c1b8,0xb2c25e),
            (0x4d977a,0x4d97a8),(0x4cd538,0x4cd54a),(0x4c7d70,0x4c7d88))
    return dict(schema='a7c2-cp-stream-geometry-static/1',cp_sha256=CP_SHA,
        producer='4d9796 calls 4d4298 with ROOT+184c = (instance+c)+a34; gated ROOT+17e9 != 0',
        lowres_category='b2a518/b2a520 -> b2a540: callbacks 4cc0a1/4cd20d store record+1c = 1',
        geometry_branch='4d42f8: record+1c in {1,2} selects global 1a53130+58, bypassing format record+94 table',
        format_branch='record+94 = 3 selects global+98 = 3840x2160 only on the other branch',
        later_clamp='4d457c obtains geometry through 774330; 4d4580..4644 conditionally clamps/aligned-down dimensions. Not executed here.',
        lowres_stream='4cd546 -> b2c36c: staged+48/+4a -> four receiver+1b8/+1ba pairs at stride70; +1b4 rounds first field up to64 units; +1b6 copies second',
        movie_stream='4c7d7e -> b2c1b8: separate per-stream source (instance+c)+a84, stride18; not the lowres uniform-copy loop',
        compatible_existing_4k_route_proven=False,physical_field_of_view_verified=False,
        alignment_unit_bytes_verified=False,isp_scaling_verified=False,encoder_handoff_verified=False,
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest()) for lo,hi in ranges],
        camera_io=False,installable=False)


def run_original(cp: bytes) -> dict:
    """Separate original init/category/pre-clamp geometry/stream-copy fragments.

    The geometry is deliberately labelled pre-clamp. No skipped helper is
    replaced by a return value; these fragments are not a live pipeline run.
    """
    check_image(cp, CP_SIZE, CP_SHA, 'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for config in range(7):
        for callback in (0x4cc0a1,0x4cd20d,0x4c79c1):
            uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
            ranges=((0x4b752e,0x4b75cc),(0xb2a482,0xb2a548),(0x4d42f8,0x4d4464),(0xb2c3ac,0xb2c3ec))
            for page in (0x4b7000,0xb2a000,0x4d4000,0xb2c000):
                uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,4096))
            glob=0x1a53130;cfg=0x21000000;record=cfg+0x200;out=cfg+0x600;receiver=cfg+0x1000
            uc.mem_map(0x1a53000,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.mem_map(cfg,0x3000,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.mem_write(cfg+0x38,struct.pack('<I',cfg));uc.mem_write(cfg+0x40,bytes([config]));uc.mem_write(record+0x94,struct.pack('<I',3))
            uc.mem_write(glob+0x98,struct.pack('<HH',3840,2160))
            write_ranges=[(glob+0x30,glob+0x34),(glob+0x50,glob+0x60),
                (record+0x14,record+0x21),(record+0x64,record+0x65),
                (out+2,out+3),(out+8,out+12),(out+0x48,out+0x4c),(receiver+0x1060,receiver+0x1061)]
            write_ranges.extend((receiver+0x1b4+i*0x70,receiver+0x1c0+i*0x70) for i in range(4))
            trace=[];stop=[0];reached=[]
            def code(em,pc,size,_):
                if pc==stop[0]:reached.append(pc);em.emu_stop();return
                if not any(lo<=pc and pc+size<=hi for lo,hi in ranges):raise ValueError('Unreviewed geometry instruction')
                if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Geometry left Thumb')
                trace.append((pc,size))
            def memory(em,access,addr,size,value,_):
                if access==u.UC_MEM_WRITE and not any(lo<=addr and addr+size<=hi for lo,hi in write_ranges):raise ValueError('Unexpected geometry write')
                if access==u.UC_MEM_READ and (0x4b753a<=addr and addr+size<=0x4b7541 or 0x4d4370<=addr and addr+size<=0x4d438a):return
                if not (cfg<=addr and addr+size<=cfg+0x3000 or glob<=addr and addr+size<=glob+0x130):raise ValueError('Unexpected geometry access')
            uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            def run(start,end,regs):
                for reg,value in regs:uc.reg_write(reg,value)
                stop[0]=end;uc.emu_start(start|1,0,count=500,timeout=1_000_000)
                if reached[-1:]!=[end]:raise ValueError('Geometry fragment did not reach boundary')
            run(0x4b752e,0x4b75cc,((a.UC_ARM_REG_R4,glob),(a.UC_ARM_REG_R5,cfg)))
            run(0xb2a482,0xb2a548,((a.UC_ARM_REG_R0,0),(a.UC_ARM_REG_R1,1),(a.UC_ARM_REG_R4,callback),
                (a.UC_ARM_REG_R6,record),(a.UC_ARM_REG_R9,0x4cc0a1),(a.UC_ARM_REG_R10,0x4cb575),
                (a.UC_ARM_REG_R12,0x4c9b2d),(a.UC_ARM_REG_LR,0xb2a827)))
            category=struct.unpack('<I',uc.mem_read(record+0x1c,4))[0]
            if category!=(0 if callback==0x4c79c1 else 1):raise ValueError('Stage category changed')
            run(0x4d42f8,0x4d4464,((a.UC_ARM_REG_R6,record),(a.UC_ARM_REG_R10,out),(a.UC_ARM_REG_R8,cfg)))
            dimensions=struct.unpack('<HH',uc.mem_read(out+0x48,4))
            if dimensions!=((3840,2160) if callback==0x4c79c1 else struct.unpack('<HH',uc.mem_read(glob+0x58,4))):raise ValueError('Wrong geometry source')
            if callback!=0x4c79c1:run(0xb2c3ac,0xb2c3ec,((a.UC_ARM_REG_R0,1),(a.UC_ARM_REG_R4,receiver),(a.UC_ARM_REG_R5,out)))
            streams=[]
            for i in range(0 if callback==0x4c79c1 else 4):
                values=struct.unpack('<4H',uc.mem_read(receiver+0x1b4+i*0x70,8))
                if values!=((dimensions[0]+63)&0xffc0,dimensions[1],*dimensions):raise ValueError('Stream geometry differs')
                streams.append(list(values))
            cases.append(dict(declared_config_byte=config,callback=hex(callback),record_category=category,
                pre_clamp_dimensions=list(dimensions),lowres_stream_fragment_executed=callback!=0x4c79c1,stream_fields_1b4_to_1ba=streams,instructions=len(trace),
                instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest()))
    return dict(schema='a7c2-cp-stream-geometry-original/1',cp_sha256=CP_SHA,cases=cases,
        fragments_executed_separately=True,live_config_verified=False,later_clamp_executed=False,
        staged_lifecycle_executed=False,actual_stream_output_verified=False,isp_executed=False,
        encoder_handoff_verified=False,camera_io=False,installable=False)


def run_geometry_lookup(cp: bytes) -> dict:
    """Complete original 774330 helper and read-only lookup callees, no stubs."""
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for mode in (0x5002,0x5004):
        for flag5,flag6 in ((0,0),(1,0),(0,1)):
            uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
            for page,size in ((0x774000,0x1000),(0x273000,0x1000),(0xd5e000,0x2000),(0x4d4000,0x1000)):
                uc.mem_map(page,size,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,size))
            base=0x21000000;sp=base+0x800;out=base+0x900;end=0x774350
            uc.mem_map(base,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.mem_write(out,b'\xa5'*12)
            uc.mem_write(sp,struct.pack('<III',out,out+4,out+8))
            for reg,value in ((a.UC_ARM_REG_R0,mode),(a.UC_ARM_REG_R1,0),(a.UC_ARM_REG_R2,flag5),
                (a.UC_ARM_REG_R3,flag6),(a.UC_ARM_REG_SP,sp),(a.UC_ARM_REG_LR,end|1)):
                uc.reg_write(reg,value)
            trace=[];done=[];boundary=[end]
            def code(em,pc,size,_):
                if pc==boundary[0]:done.append(pc);em.emu_stop();return
                if not any(lo<=pc and pc+size<=hi for lo,hi in ((0x774280,0x774350),(0x2731f8,0x2736b0),(0x273a3c,0x273bba),(0x4d4580,0x4d4648))):raise ValueError('Unreviewed geometry lookup instruction')
                if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Geometry lookup left Thumb')
                trace.append((pc,size))
            def memory(em,access,addr,size,value,_):
                if access==u.UC_MEM_WRITE:
                    if not (sp-0x80<=addr and addr+size<=sp or out<=addr and addr+size<=out+(16 if boundary[0]!=end else 12)):raise ValueError('Unexpected geometry lookup write')
                elif boundary[0]!=end and (out<=addr and addr+size<=out+16 or base+0xa18<=addr and addr+size<=base+0xa20):return
                elif not (sp-0x80<=addr and addr+size<=sp+12 or out<=addr and addr+size<=out+12 or
                          0x27328c<=addr and addr+size<=0x273296 or 0x273aaa<=addr and addr+size<=0x273aaf or
                          any(ptr+0x1a4<=addr and addr+size<=ptr+0x1a8 for ptr in (0xd5e590,0xd5f148))):
                    raise ValueError('Unexpected geometry lookup read')
            uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(0x774331,0,count=500,timeout=1_000_000)
            if not done or uc.reg_read(a.UC_ARM_REG_SP)!=sp:raise ValueError('Geometry lookup did not return cleanly')
            ret=uc.reg_read(a.UC_ARM_REG_R0);raw=bytes(uc.mem_read(out,12))
            expected=struct.unpack('<HH',cp_span(cp,(0xd5e590 if mode==0x5002 else 0xd5f148)+0x1a4,4))
            if (flag5,flag6)==(0,0):
                if ret!=0 or struct.unpack('<HH',raw[:4])!=expected or raw[4:]!=b'\xa5'*8:raise ValueError('Geometry lookup result differs')
            elif ret!=11 or raw!=b'\xa5'*12:raise ValueError('Geometry lookup rejection differs')
            clamped=None
            if ret==0:
                # The 4cd20d builder's original category/kind are 1/1.
                # This continuation consumes the helper's actual output, not a stub.
                uc.mem_write(base+0xa18,struct.pack('<II',1,1))
                uc.mem_write(out+12,struct.pack('<HH',2048,1364))
                uc.reg_write(a.UC_ARM_REG_R6,base+0xa00);uc.reg_write(a.UC_ARM_REG_R10,out-0x3c)
                boundary[0]=0x4d4648;uc.emu_start(0x4d4581,0,count=100,timeout=1_000_000)
                clamped=list(struct.unpack('<HH',uc.mem_read(out+12,4)))
                if done[-1:]!=[0x4d4648] or clamped!=[1024,682]:raise ValueError('Geometry clamp differs')
            cases.append(dict(mode=hex(mode),declared_record_flag5=flag5,declared_record_flag6=flag6,
                return_code=ret,declared_pre_clamp_geometry=[2048,1364],callback_4cd20d_conditional_clamp=clamped,geometry=list(expected) if ret==0 else None,output_unchanged_on_rejection=raw==b'\xa5'*12,
                instructions=len(trace),instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest()))
    return dict(schema='a7c2-cp-geometry-lookup-original/1',cp_sha256=CP_SHA,cases=cases,
        helper='0x774330 -> 0x774280 -> 0x273a3c/0x2731f8',caller='0x4d457c',
        caller_flag_provenance_verified=False,conditional_4cd20d_clamp_executed=True,other_callback_clamp_executed=False,physical_sensor_dimensions_verified=False,
        spatial_coverage_verified=False,camera_io=False,installable=False)
