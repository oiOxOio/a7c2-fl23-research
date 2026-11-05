"""Pinned AVBBC control receiver and pin-request provenance, not pixel execution."""
from __future__ import annotations
import hashlib
import struct
from request_trace import Elf64, check_image, span
from ap_xrefs import imported_slots
SIZE = 1738760
SHA = '676197567dbbefa54e08f528968efc6ca2aaffe8bee3ee3eae8164382ed5a7e5'


def _virtual_bindings(e: Elf64) -> list[dict]:
    """Resolve three original ABS64 symbol relocations; not runtime interposition."""
    expected={0x1a8df0:0xae75c,0x1a8080:0xa41b0,0x1a80d0:0xa46e4}
    result=[]
    for sec in e.sections:
        if sec[1]!=4:continue
        if sec[9]!=24 or sec[5]%24:raise ValueError('Invalid relocation layout')
        for p in range(sec[4],sec[4]+sec[5],24):
            slot,info,addend=struct.unpack('<QQq',span(e.data,p,24))
            if slot not in expected:continue
            if info & 0xffffffff != 257 or addend!=0:raise ValueError('Expected ABS64 binding')
            sy=e.sections[sec[6]];index=info>>32
            if sy[1]!=11 or sy[9]!=24 or index>=sy[5]//24:raise ValueError('Invalid symbol binding')
            name,_,_,_,va,size=struct.unpack('<IBBHQQ',span(e.data,sy[4]+index*24,24))
            strings=e.sections[sy[6]];names=span(e.data,strings[4],strings[5]);end=names.find(b'\0',name)
            if end<name or va!=expected[slot]:raise ValueError('Virtual symbol differs')
            result.append(dict(slot=hex(slot),target=hex(va),name=names[name:end].decode('ascii'),size=size,
                relocation_sha256=hashlib.sha256(span(e.data,p,24)).hexdigest(),runtime_binding_verified=False))
    if len(result)!=3:raise ValueError('Missing virtual bindings')
    return result


def inspect(data: bytes) -> dict:
    check_image(data, SIZE, SHA, 'original libInfraAvbbc.so')
    e = Elf64(data)
    ranges = ((0xa2e7c,0xa2e98),(0x138f14,0x138f30),(0x139b9c,0x139bec),
              (0xa2ad8,0xa2c5c),(0xadfc4,0xadfe8),(0x13a194,0x13a224),
              (0xae75c,0xae7e8),(0xb05fc,0xb0618),(0xbad90,0xbaf64),
              (0xbd1a0,0xbd268),(0xbd3c4,0xbd504),(0x129b74,0x129c0c),
              (0xa41b0,0xa427c),(0xa46e4,0xa47a8),(0x129444,0x129490),(0x1296ac,0x129770),(0x1299f0,0x129a14),(0xb1a10,0xb1a30))
    return dict(schema='a7c2-avbbc-receiver-static/1', component_sha256=SHA,
        virtual_bindings=_virtual_bindings(e),
        receiver=dict(constructor='a2e88..94 constructs MsgManager(0x8055001f)',
            queue_storage='138f18 stores unmodified constructor QID at manager+8',
            receive='139b9c..bd0 ReceiveASync(manager+8), GetMsg copies 0x30 envelope to output+8',
            routing='a2ad8..c58 message 0x210 command 6 chooses 0x80550122; command 7/8/15/16 selects 0x805502f2',
            encoder_constructor='adfd0..e4 constructs MsgManager(0x80550122)',
            dispatch_candidate='13a194..21c requires source 0x8055001f and non-Biz branch; virtual+0x30 receives wrapper+8',
            factory='ae7b4..e0 invokes factory with payload message+0x24 and command+2; command 6 branches b05fc to EncStart2Astra constructor',
            actual_delivery_verified=False),
        pin_control=dict(sequence='EncStart2Astra ba6e0 constructs paired MCSDF_PinGet and INFRA_PinReqConnect commands',
            source_descriptor='badb4..e00 source QID 0x82830752, parameter key 0x103c, numeric direction 1; pin from GetSdfPinNo',
            codec_descriptor='bada8..df0 fixed QID 0x805700f9, parameter key 0x1004, numeric direction 2, pin 1',
            binding='baf28..3c passes those same two descriptor addresses to PinReqConnect; constructor129bd4..bfc copies 20 bytes each',
            response_gate='bd3c4 accepts response 0x8f01, matches response+0xc against descriptor direction; waits for both successful PinGet responses',
            registry_implementation='ABS64 vtable bindings identify SetValue a41b0 and GetValue a46e4; lookup MWF::ObjMsg by key, copy into MWF::Struct, return stored struct/pointer only for supported types; absent keys are not fabricated',
            response_registration='129468 requires status at response+0x1c zero;129474..48c stores full 0x20-byte response through ParameterControl+0x60 at original descriptor key',
            connect_payload='1296ac..738 virtual ParameterControl+0xb0 resolves keys from each descriptor; copies returned +8/+c/+10/+18 into 0x28-byte connect request',
            missing='actual response-created pin records, source implementation and pixel buffer/address/geometry linkage remain unresolved'),
        imports=imported_slots(e,{0x1b4850,0x1b55f0,0x1b4d38,0x1b42c0,0x1b6458,
            0x1b4a98,0x1b5f08,0x1b6c08,0x1b5610}),
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(span(data,e.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ranges],
        static_control_link_not_pixel_buffer=True, raw_pixel_producer_identified=False,
        physical_readout_verified=False,camera_io=False,installable=False)


def run_original(data: bytes) -> dict:
    """Execute original router fragment and complete leaf pin-number function only."""
    check_image(data,SIZE,SHA,'original libInfraAvbbc.so');e=Elf64(data)
    import unicorn as u
    from unicorn import arm64_const as a
    import struct
    uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
    for page in (0xa2000,0xb1000):
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        uc.mem_write(page,span(data,e.file_offset(page,4096),4096))
    base=0x21000000;uc.mem_map(base,4096);trace=[];limit=[0]
    def hook(em,pc,size,_):
        if pc==limit[0]:em.emu_stop();return
        if size!=4 or not (0xa2ad8<=pc<0xa2b04 or 0xa2b80<=pc<0xa2b88 or 0xa2bb8<=pc<0xa2bc0 or 0xa2c28<=pc<0xa2c5c or 0xb1a10<=pc<0xb1a30):raise ValueError('Unexpected AVBBC instruction')
        trace.append(pc)
    uc.hook_add(u.UC_HOOK_CODE,hook)
    initial=bytes(b'\xa5'*4096);routes=[]
    for command in (6,7,8,15,16):
        buf=bytearray(initial);struct.pack_into('<I',buf,0x84,0x210);struct.pack_into('<H',buf,0x62,command)
        uc.mem_write(base,bytes(buf));uc.reg_write(a.UC_ARM64_REG_X29,base);limit[0]=0xa2c8c
        uc.emu_start(0xa2ad8,limit[0],count=80)
        dest=uc.reg_read(a.UC_ARM64_REG_W19)
        if uc.reg_read(a.UC_ARM64_REG_PC)!=limit[0] or dest!=(0x80550122 if command==6 else 0x805502f2):raise ValueError('AVBBC routing differs')
        if bytes(uc.mem_read(base,4096))!=bytes(buf):raise ValueError('Router modified memory')
        routes.append(dict(command=command,destination=hex(dest)))
    pins=[]
    for value in (0,5,6,7,15,255):
        buf=bytearray(initial);buf[0x24]=value;uc.mem_write(base,bytes(buf));uc.reg_write(a.UC_ARM64_REG_X0,base)
        uc.reg_write(a.UC_ARM64_REG_LR,0xb1a30);limit[0]=0xb1a30;uc.emu_start(0xb1a10,limit[0],count=20)
        if uc.reg_read(a.UC_ARM64_REG_PC)!=limit[0]:raise ValueError('Pin leaf did not return')
        pin=uc.reg_read(a.UC_ARM64_REG_W0)
        if pin!=(3 if value in (5,6,15) else 4) or bytes(uc.mem_read(base,4096))!=bytes(buf):raise ValueError('Pin leaf differs')
        pins.append(dict(input_byte=value,pin=pin))
    return dict(schema='a7c2-avbbc-receiver-original/1',component_sha256=SHA,routes=routes,pins=pins,
        instructions=len(trace),instruction_stream_sha256=hashlib.sha256(b''.join(span(data,e.file_offset(pc,4),4) for pc in trace)).hexdigest(),
        fragments_executed_separately=True,queue_operations_executed=False,virtual_dispatch_executed=False,
        source_descriptor_inputs_declared=True,pixel_buffers_executed=False,camera_io=False,installable=False)

DATAFLOW_SIZE = 306496
DATAFLOW_SHA = '620e04a9cd51e65bd190ed1d5459b7235ff5a4109bc6498df342972621991d47'


def inspect_dataflow(data: bytes) -> dict:
    """The sender copies a control envelope, not the sensor pixel surface."""
    check_image(data,DATAFLOW_SIZE,DATAFLOW_SHA,'original dataflowInfraFramework.so')
    e=Elf64(data)
    return dict(schema='a7c2-dataflow-pin-transport-static/1',component_sha256=DATAFLOW_SHA,
        sender='DataflowInfraSender::SendASync at34110',
        steps=['34168 allocates message for caller destination QID',
               '341b4..c4 copies envelope bytes from object+18',
               '341c8..d0 sets source ID from object+10',
               '341d4..dc submits same destination QID and allocated message'],
        imports=imported_slots(e,{0x5a230,0x5a1a0,0x5a068}),
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(span(data,e.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ((0x32564,0x32698),(0x34110,0x34230))],
        envelope_size_not_pixel_size=True,kernel_queue_route_verified=False,
        pixel_producer_identified=False,transport_executed=False,camera_io=False,installable=False)

KERNEL_SIZE = 76360
KERNEL_SHA = 'f0eb3a32a9d339066600e012aa3e91de31419c173e3fe5c1cc44aa9188763095'


def inspect_kernel(data: bytes) -> dict:
    """Read ET_REL section coordinates only; never relocate or load the module."""
    check_image(data,KERNEL_SIZE,KERNEL_SHA,'original osal_uipc.ko')
    if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<HH',data,16)!=(1,183):
        raise ValueError('Expected AArch64 ET_REL')
    return dict(schema='a7c2-kernel-queue-boundary-static/1',component_sha256=KERNEL_SHA,
        coordinates='all instruction addresses are .text section offsets, NOT loaded virtual addresses; .text file offset=0x68',
        destination='0x82830752',local_queue_index='0x0752',
        branch='osal_snd_msg .text+3c5c tests bit31;3d78 tests mask0x70000000 (zero for82830752), returns to3c60 local lookup; does NOT take public callback3d94',
        lookup='2938..2974: .bss+2bc0 base, root+220+(index>>9 &63)*8, then indices(index>>6 &7),(index>>3 &7),(index &7)',
        required_runtime_objects='queue indices3/5/2/2; queue+8 callback chain, queue+10/+18 pending-message list and queue+38 lock',
        registration='reg_msg_queue_cb5278..532c obtains same queue through2938 or creation2ee8 and appends supplied callback node to queue+8',
        missing='static module does not provide live queue0x0752 registration/consumer identity; CP SdfPinGet RTTI candidate alone cannot close this edge',
        ranges=[dict(section_offset=hex(lo),end=hex(hi),sha256=hashlib.sha256(span(data,0x68+lo,hi-lo)).hexdigest()) for lo,hi in ((0x2938,0x2978),(0x3bf8,0x3e00),(0x5278,0x532c))],
        kernel_loaded=False,runtime_registration_verified=False,cp_target_proven=False,camera_io=False,installable=False)


def inspect_ap_topology(data: bytes) -> dict:
    from request_trace import AP_SIZE, AP_SHA
    check_image(data,AP_SIZE,AP_SHA,'original appFw.so');e=Elf64(data)
    names={0x4c9fb8e:b'SDT\0',0x4c9fac2:b'pin_manager.cpp\0',0x4c9fcf0:b'change_infra_pin_topology\0'}
    for va,value in names.items():
        if span(data,e.file_offset(va,len(value)),len(value))!=value:raise ValueError('Topology identity differs')
    return dict(schema='a7c2-ap-pin-topology-static/1',component_sha256=AP_SHA,
        source_label=dict(qid='0x82830752',label='SDT',instruction='35a8d34..4c',label_va='0x4c9fb8e'),
        descriptors=dict(codec=dict(va='0x95645b8',fields=['0x805700f9',0,2,1],initializer='1716054..70'),
            sdt=dict(va='0x9564178',fields=['0x82830752',0,1,3],initializer='1716140..58'),
            constants='17158b4 sets w1=2;1715914 sets w0=1'),
        topology=dict(example_got='0x5ba4ef8',table_entry_offset='0x438',entry_stride='0x18',entry_index=45,
            stores='1717868..84 stores codec descriptor at+438,status1 at+440,SDT descriptor at+448',
            selector='35a9e40 checks input+4/+0;35a9ed0..ef0 chooses example on input+8 !=0 and input+10 !=0 within selected case',
            consumer='35a9880 traverses50 entries;copies two16-byte endpoint records to stack;35a9c94 invokes351135c on ordinary branch,35a9acc invokes35115b8 on alternate branch',
            ordinary_ui_mode_semantics_verified=False),
        relation_to_avbbc='AVBBC pin3 is chosen only for wrapper+24 values5,6,15; other byte values choose pin4. The profile conversion companion proves numeric compatibility for the validated AVC Long profile, not actual runtime use or pixel content.',
        wrapper_field_provenance='ba784..794 copies38-byte wrapper;GetSdfPinNo(b1a10) reads wrapper+24, i.e. enclosed MPR codec envelope+1c, not movieRecParam file-format enum',
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(span(data,e.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ((0x17158b4,0x17158b8),(0x1715914,0x1715918),(0x1716010,0x1716074),(0x1716134,0x171615c),(0x17175a4,0x17175b0),(0x1717868,0x1717888),(0x35a8d34,0x35a8d50),(0x35a9e40,0x35a9ef4),(0x35a9c38,0x35a9cb8))],
        osal_queue_consumer_identified=False,pixel_geometry_verified=False,full_fov_verified=False,camera_io=False,installable=False)


def run_profile_pin(mpr: bytes, avbbc: bytes) -> dict:
    """Independent original conversion/leaf fragments; not MovieRecInfo delivery."""
    from mpr_bitrate import SIZE as MS, SHA as MH
    check_image(mpr,MS,MH,'original libmpr.so');check_image(avbbc,SIZE,SHA,'original libInfraAvbbc.so')
    me,ae=Elf64(mpr),Elf64(avbbc)
    import unicorn as u
    from unicorn import arm64_const as a
    uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
    for page,data,e in ((0xce000,mpr,me),(0x2fc000,mpr,me),(0x2cd000,mpr,me),(0xb1000,avbbc,ae)):
        uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        uc.mem_write(page,span(data,e.file_offset(page,4096),4096))
    # Resolve only the verified g_videoParamComb GLOB_DAT, not a runtime callback.
    uc.mem_write(0x2fca50,struct.pack('<Q',0x2cdb08))
    base=0x21000000;uc.mem_map(base,4096);trace=[];stop=[0]
    def code(em,pc,size,_):
        if pc==stop[0]:em.emu_stop();return
        if size!=4 or not (0xceba0<=pc<0xcebd8 or 0xcec20<=pc<0xcec3c or 0xb1a10<=pc<0xb1a30):raise ValueError('Unexpected profile-pin instruction')
        trace.append(pc)
    uc.hook_add(u.UC_HOOK_CODE,code);cases=[]
    for profile,stream,expected,pin in ((2,0,5,3),(0,0,5,3),(9,0,20,4),(4,0,15,3),(2,1,17,4)):
        uc.reg_write(a.UC_ARM64_REG_X19,profile);uc.reg_write(a.UC_ARM64_REG_W20,stream);stop[0]=0xcebd8
        uc.emu_start(0xceba0,stop[0],count=50)
        value=uc.reg_read(a.UC_ARM64_REG_W19)
        if uc.reg_read(a.UC_ARM64_REG_PC)!=stop[0] or value!=expected:raise ValueError('Codec profile conversion differs')
        initial=bytearray(b'\xa5'*4096);initial[0x24]=value;uc.mem_write(base,bytes(initial))
        uc.reg_write(a.UC_ARM64_REG_X0,base);uc.reg_write(a.UC_ARM64_REG_LR,0xb1a30);stop[0]=0xb1a30
        uc.emu_start(0xb1a10,stop[0],count=20)
        if uc.reg_read(a.UC_ARM64_REG_PC)!=stop[0] or uc.reg_read(a.UC_ARM64_REG_W0)!=pin or bytes(uc.mem_read(base,4096))!=bytes(initial):raise ValueError('Codec pin conversion differs')
        cases.append(dict(profile=profile,stream=stream,codec_file_format=value,sdt_pin=pin))
    return dict(schema='a7c2-codec-profile-pin-original/1',mpr_sha256=MH,avbbc_sha256=SHA,cases=cases,
        table='g_videoParamComb at2cdb08, stride24; converter reads+0/+14',
        settings_storage_chain=['SetMovieRecParam f2bbc..bc8 copies1d5 caller bytes to38f238',
            'GetMovieRecParam f2d8c..9c copies1d5 bytes from38f238',
            'SetEnterRecInfo helper cdf34 calls GetMovieRecParam and CheckMovieRecParam; success ce048..54 copies1d5 bytes toMovieRecInfo+58',
            '58+178=1d0: exact same profile field, not merely equal offsets in unrelated objects'],
        storage_imports=imported_slots(me,{0x301778,0x2ff040,0x2fe178,0x2ff238,0x2ff700,0x300f20}),
        provenance_ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(span(mpr,me.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ((0xf2bbc,0xf2bcc),(0xf2d6c,0xf2db8),(0xcdf34,0xcdf78),(0xce048,0xce058),(0xd8108,0xd8114),(0xcbcd0,0xcbcec),(0xcbe10,0xcbe2c))],
        enqueue_coordinates='d8108..1110 MovieRecInfo+1d0 -> converter(stream0) -> execEncStart+14',
        caller_coordinates='cbc20:exec+14 -> Codec::EncStart w2 or EncStart2 w2; original imported signatures identify codec FileFormat',
        instructions=len(trace),instruction_stream_sha256=hashlib.sha256(b''.join(span(mpr,me.file_offset(pc,4),4) if pc>=0xce000 else span(avbbc,ae.file_offset(pc,4),4) for pc in trace)).hexdigest(),
        table_sha256=hashlib.sha256(span(mpr,me.file_offset(0x2cdb08,336),336)).hexdigest(),
        fragments_executed_separately=True,
        declared_symbol_relocation=True,continuous_setting_to_movie_record_proven=False,
        enqueue_or_encoder_executed=False,actual_pin_contents_verified=False,full_fov_verified=False,camera_io=False,installable=False)
