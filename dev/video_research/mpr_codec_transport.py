"""Original MPR codec control transport, distinct from pixel-source binding."""
from __future__ import annotations
import hashlib
import struct
from request_trace import Elf64,check_image,span
from ap_xrefs import imported_slots
from mpr_bitrate import SIZE,SHA


def inspect(data:bytes)->dict:
    check_image(data,SIZE,SHA,'original libmpr.so');e=Elf64(data)
    expected={'_ZN3mpr5Codec14SendMsgToAvbbcEP10PayloadMprP12PayloadCodec':(0x27c058,376),
        '_ZN3mpr5Codec25SetUserIdReadPointerTableERKSt6vectorIjSaIjEERS1_INS0_13UserInfoTableESaIS6_EE':(0x281ef8,204)}
    exports=[s for s in e.symbols() if s['name'] in expected]
    if len(exports)!=len(expected) or any((s['va'],s['size'])!=expected[s['name']] for s in exports):raise ValueError('Codec exports differ')
    ranges=((0x2c8b88,0x2c8b90),(0x27e264,0x27e2b8),(0x27be38,0x27bed0),
        (0x27c058,0x27c1d0),(0x283b68,0x283ce4),(0x281ef8,0x281fc4))
    return dict(schema='a7c2-mpr-codec-transport-static/1',component_sha256=SHA,
        exports=exports,encstart2=dict(entry='0x27e10c',message_id='0x210',command_id=6,body_bytes=0x100,
            packaging='27e264..28c prepares CreateMessage;27e290..29c copies caller body;27e2a8 invokes SendMsgToAvbbc'),
        envelope=dict(size=0x30,command_offset=2,body_pointer_offset=8,body_size_offset=0x10,
            codec_fields=['0x18','0x19'],view_id_offset='0x1a',format_fields=['0x1c','0x1e'],
            message_id_offset='0x24',second_allocation_pointer_offset='0x28'),
        transport=dict(destination='0x8055001f',source='0x80c70047',
            allocation='27c084 -> osal_valloc_msg_wait',source_set='27c12c -> osal_set_msg_src',
            submission='27c13c -> osal_snd_msg',completion_wait='27c1a4 -> pthread_cond_wait',
            distinction='earlier SetMovieRecParam sends to0x008f013a; these are different control stages',
            receiver_component_or_handler_verified=False,actual_delivery_verified=False),
        source_api_negative_control='MprIf::SetRecSource at2c8b88 is only mov w0,0;ret; no source binding',
        buffer_api_scope='SetBufferInfo283b68 populates UserInfoTable vectors through281ef8 from caller uint32 IDs; do not infer raw sensor/ISP pixel addresses from the name',
        imports=imported_slots(e,{0x2fe208,0x301200,0x2ff708,0x2fe4f0,0x2ff138,0x301b38,0x2ff560}),
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(span(data,e.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ranges],
        control_message_is_pixel_buffer=False,raw_pixel_producer_identified=False,
        encoder_executed=False,camera_io=False,installable=False)


def run_original(data:bytes)->dict:
    check_image(data,SIZE,SHA,'original libmpr.so');e=Elf64(data)
    import unicorn as u
    from unicorn import arm64_const as a
    uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
    for page in (0x2c8000,0x27e000,0x27b000):
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,span(data,e.file_offset(page,4096),4096))
    base=0x21000000;frame=base+0x100;payload=base+0x800
    uc.mem_map(base,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);initial=bytearray(b'\xa5'*4096)
    struct.pack_into('<Q',initial,0x160,0x22000000);struct.pack_into('<Q',initial,0x168,0x23000000)
    struct.pack_into('<I',initial,0x170,0)
    uc.mem_write(base,bytes(initial));trace=[];stop=[0];done=[];phase=[0]
    ranges=((0x2c8b88,0x2c8b90),(0x27e264,0x27e28c),(0x27be84,0x27bec4))
    def code(em,pc,size,_):
        if pc==stop[0]:done.append(pc);em.emu_stop();return
        if size!=4 or not any(lo<=pc and pc+size<=hi for lo,hi in ranges):raise ValueError('Unexpected codec instruction')
        trace.append(pc)
    writes=[(frame,frame+4),(payload+2,payload+4),(payload+8,payload+0xc),(payload+8,payload+0x10),
        (payload+0x10,payload+0x14),(payload+0x18,payload+0x20),(payload+0x24,payload+0x30)]
    def memory(em,access,addr,size,value,_):
        if phase[0]==0:raise ValueError('Stub source setter accessed memory')
        if access==u.UC_MEM_WRITE:
            if not any(lo<=addr and addr+size<=hi for lo,hi in writes):raise ValueError('Unexpected codec header write')
        elif not frame+0x20<=addr or addr+size>frame+0x74:raise ValueError('Unexpected codec header read')
    uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
    def run(start,end,regs):
        for reg,value in regs:uc.reg_write(reg,value)
        stop[0]=end;uc.emu_start(start,end,count=100,timeout=1_000_000)
        if uc.reg_read(a.UC_ARM64_REG_PC)!=end:raise ValueError('Codec fragment boundary differs')
    run(0x2c8b88,0x2c8b90,((a.UC_ARM64_REG_X0,0xdead0000),(a.UC_ARM64_REG_X1,0xffffffff),(a.UC_ARM64_REG_LR,0x2c8b90)))
    if uc.reg_read(a.UC_ARM64_REG_W0)!=0:raise ValueError('Source API stub differs')
    phase[0]=1
    run(0x27e264,0x27e28c,((a.UC_ARM64_REG_SP,frame),(a.UC_ARM64_REG_X20,payload),
        (a.UC_ARM64_REG_W25,2),(a.UC_ARM64_REG_W26,3),(a.UC_ARM64_REG_W27,4),(a.UC_ARM64_REG_W28,5)))
    args=[uc.reg_read(r) for r in (a.UC_ARM64_REG_W0,a.UC_ARM64_REG_W1,a.UC_ARM64_REG_W4)]
    if args!=[0x210,6,0x100]:raise ValueError('EncStart2 message arguments differ')
    run(0x27be84,0x27bec4,((a.UC_ARM64_REG_X29,frame),(a.UC_ARM64_REG_X19,payload),
        (a.UC_ARM64_REG_W24,args[0]),(a.UC_ARM64_REG_W25,args[1]),(a.UC_ARM64_REG_W26,args[2]),
        (a.UC_ARM64_REG_W23,2),(a.UC_ARM64_REG_W22,3),(a.UC_ARM64_REG_W21,4),(a.UC_ARM64_REG_W20,5)))
    raw=bytes(uc.mem_read(payload,0x30))
    if struct.unpack_from('<H',raw,2)[0]!=6 or struct.unpack_from('<I',raw,0x24)[0]!=0x210 or struct.unpack_from('<I',raw,0x10)[0]!=0x100:raise ValueError('Codec header differs')
    if struct.unpack_from('<Q',raw,8)[0]!=0x22000000 or struct.unpack_from('<Q',raw,0x28)[0]!=0x23000000:raise ValueError('Codec pointer copy differs')
    actual=bytes(uc.mem_read(base,4096))
    if any(x!=y and not any(lo<=base+i<hi for lo,hi in writes) for i,(x,y) in enumerate(zip(initial,actual))):raise ValueError('Codec memory canary differs')
    return dict(schema='a7c2-mpr-codec-transport-original/1',component_sha256=SHA,
        source_setter_return=0,source_setter_memory_accesses=0,encstart2_message_id=hex(args[0]),command_id=args[1],body_size=args[2],
        instructions=len(trace),instruction_stream_sha256=hashlib.sha256(b''.join(span(data,e.file_offset(pc,4),4) for pc in trace)).hexdigest(),
        fragments_executed_separately=True,allocation_pointers_declared_not_allocated=True,
        allocator_executed=False,body_copy_executed=False,transport_executed=False,encoder_executed=False,camera_io=False,installable=False)
