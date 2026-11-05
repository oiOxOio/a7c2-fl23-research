"""Pinned libmpr target bitrate lookup, not encoded-throughput evidence."""
from __future__ import annotations
import hashlib
import struct
from request_trace import Elf64,check_image,span
from ap_xrefs import imported_slots
SIZE=3528576
SHA='4fb6d886c1ac620399d09c9c2ffc074315968cf0ada764062913c4e0783fc7f9'
LOOKUP=0x2c3b54
TABLE=0x2e3628
SYMBOL='_ZN3mpr5pconv15GetVideoBitrateEN9DefStruct8VQualityE'


def inspect(data: bytes) -> dict:
    check_image(data,SIZE,SHA,'original libmpr.so');elf=Elf64(data)
    wanted={SYMBOL:(LOOKUP,36),'_ZN3mpr16SetMovieRecParamERKNS_13movieRecParamE':(0xf2b24,304)}
    exports=[]
    for symbol in elf.symbols():
        if symbol['name'] in wanted:
            if (symbol['va'],symbol['size'])!=wanted[symbol['name']] or symbol['type']!=2:
                raise ValueError('MPR export metadata differs.')
            exports.append(symbol)
    if len(exports)!=2:raise ValueError('Missing or duplicate MPR exports.')
    csv=span(data,elf.file_offset(0x2cc366,120),120).split(b'\0')[0]
    if b'vQuality,Mbps,audioParamComb' not in csv:raise ValueError('MPR bitrate unit diagnostic differs.')
    ranges=((LOOKUP,LOOKUP+36),(TABLE,TABLE+208),(0x9a4b8,0x9a4e0),
        (0x9a568,0x9a578),(0x12b104,0x12b10c),(0x12b14c,0x12b164),
        (0x104e44,0x104ecc),(0x105174,0x1051a8),(0x30a7b8,0x30a890),
        (0xf2b24,0xf2c54),(0xf29f4,0xf2b1c))
    return dict(schema='a7c2-mpr-bitrate-static/1',component_sha256=SHA,component_size=SIZE,
        exports=exports,table_va=hex(TABLE),first_enum=2,last_enum=53,
        table_values=list(struct.unpack('<52I',span(data,elf.file_offset(TABLE,208),208))),
        units=dict(lookup='kbit/s target',diagnostic='Mbps',diagnostic_va='0x2cc366',
            diagnostic_sha256=hashlib.sha256(csv+b'\0').hexdigest(),
            debug_divisor=1000,debug_division='0x9a4c4..0x9a4d0',
            bytes_per_second_conversion='0x12b108 sets 1000; 0x12b154 multiplies; 0x12b160 divides by 8'),
        imports=imported_slots(elf,{0x2fed08}),
        media_check=dict(function='0x104e44',dispatch='0x105174',
            dispatch_profile_values=[0,2],quality_field='movieRecParam +0x17c',
            rate_field='movieRecParam +0x180',proxy_field='movieRecParam +0x1a6',
            table='0x30a7b8',row_size=12,row_count=18,
            rows=[list(struct.unpack('<II4B',span(data,elf.file_offset(0x30a7b8+i*12,12),12)))
                  for i in range(18)],
            result_semantics='media transfer-rate check category, not sensor capability',
            table_runtime_mutability_verified=False,actual_media_tested=False),
        parameter_submission=dict(entry='0xf2b24',helper='0xf29f4',
            first_subcommand=0x10,second_subcommand=0x11,destination='0x008f013a',
            parameter_copy_size=0x1d5,
            transport_imports=imported_slots(elf,{0x2ff708,0x2fe4f0,0x2ff138}),
            unconditional_zero_return='0xf2c30',
            transport_executed=False,receiver_verified=False,
            equivalent_to_cp_imaging_transport_verified=False,
            zero_return_proves_recording=False),
        ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(
            span(data,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ranges],
        runtime_import_binding_verified=False,encoder_invoked=False,
        measured_bitrate_verified=False,uncropped_capability_verified=False,camera_io=False)


def run_original(data: bytes) -> dict:
    check_image(data,SIZE,SHA,'original libmpr.so');elf=Elf64(data)
    import unicorn as u
    from unicorn import arm64_const as a
    results=[]
    for quality,expected in ((22,200000),(13,150000),(37,140000),(12,100000),(10,60000),
                             (0,0),(1,0),(54,0),(0xffffffff,0)):
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for page in (0x2c3000,0x2e3000,0x9a000):
            uc.mem_map(page,4096,u.UC_PROT_READ|(0 if page==0x2e3000 else u.UC_PROT_EXEC))
            uc.mem_write(page,span(data,elf.file_offset(page,4096),4096))
        fp=0x10000000;uc.mem_map(fp,4096,u.UC_PROT_READ);uc.mem_write(fp,b'\xa5'*4096)
        # Only unrelated debug-context loads are explicitly supplied; no BSS/driver state.
        for off in (0x6c,0x78,0x7c):uc.mem_write(fp+off,struct.pack('<I',0))
        uc.reg_write(a.UC_ARM64_REG_X29,fp);uc.reg_write(a.UC_ARM64_REG_LR,0xdead0000)
        uc.reg_write(a.UC_ARM64_REG_W0,quality)
        path=[]
        def code(em,pc,size,_):
            if size!=4 or not (LOOKUP<=pc<LOOKUP+36 or 0x9a4c4<=pc<0x9a4d4):
                raise ValueError('Unexpected MPR bitrate instruction.')
            path.append(pc)
        def memory(em,access,addr,size,value,_):
            allowed=access==u.UC_MEM_READ and ((TABLE<=addr and addr+size<=TABLE+208)
                or (fp+0x6c<=addr and addr+size<=fp+0x70)
                or (fp+0x78<=addr and addr+size<=fp+0x80))
            if not allowed:raise ValueError('Unexpected MPR bitrate memory access.')
        uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(LOOKUP,0xdead0000,count=20,timeout=1_000_000)
        value=uc.reg_read(a.UC_ARM64_REG_W0)
        if value!=expected or uc.reg_read(a.UC_ARM64_REG_PC)!=0xdead0000:raise ValueError('MPR bitrate lookup differs.')
        uc.emu_start(0x9a4c4,0x9a4d4,count=10,timeout=1_000_000)
        mbps=uc.reg_read(a.UC_ARM64_REG_W0)
        if mbps!=expected//1000 or uc.reg_read(a.UC_ARM64_REG_PC)!=0x9a4d4:
            raise ValueError('MPR original debug conversion differs.')
        results.append(dict(quality_enum=quality,target_kbps=value,diagnostic_mbps=mbps,
            instruction_stream_sha256=hashlib.sha256(b''.join(span(data,elf.file_offset(pc,4),4) for pc in path)).hexdigest()))
    return dict(schema='a7c2-mpr-bitrate-original/1',component_sha256=SHA,
        case_count=len(results),cases=results,debug_context_synthetic=True,
        lookup_and_debug_fragments_separate=True,unknown_helpers_executed=0,
        encoder_invoked=False,recording_verified=False,measured_bitrate_verified=False,
        uncropped_capability_verified=False,camera_io=False,installable=False)


def run_parameter_chain(ap: bytes,data: bytes) -> dict:
    """Join independently executed original fragments by proven enum coordinates."""
    from ap_mpr_encoding import run_original as encode
    encoded=encode(ap);bitrate=run_original(data)
    by_enum={case['quality_enum']:case for case in bitrate['cases']}
    cases=[]
    for case in encoded['cases']:
        value=by_enum[case['quality_enum']]
        cases.append(dict(setting_rate=case['setting_rate'],quality_setting=case['quality_setting'],
            codec_profile=case['names'][0]['text'],frame_rate_name=case['names'][1]['text'],
            quality_enum=case['quality_enum'],target_kbps=value['target_kbps'],
            target_mbps=value['diagnostic_mbps']))
    return dict(schema='a7c2-mpr-target-parameter-chain/1',ap_sha256=encoded['ap_sha256'],
        mpr_sha256=SHA,cases=cases,independent_original_fragments=True,
        continuous_execution_verified=False,encoder_invoked=False,
        measured_bitrate_verified=False,uncropped_capability_verified=False,camera_io=False,installable=False)
