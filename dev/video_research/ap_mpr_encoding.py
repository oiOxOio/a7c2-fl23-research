"""Original MPR format/quality/rate conversion and original diagnostic naming.

The wrapper fragment is separate from the model builder and stops before helpers.
These are target parameter enums, not measured encoding or bitrate evidence.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE,AP_SHA,Elf64,check_image,span
from ap_mpr_quality import run_original as run_builder
from ap_xrefs import imported_slots


def inspect(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    spans=((0x3574578,0x35745a4),(0x3574824,0x3574850),(0x35748d8,0x35748e8),
        (0x3574948,0x3574958),(0x3574a54,0x3574b58),(0x3574e0c,0x3574e44),
        (0x3559834,0x3559904),(0x3559904,0x3559990),
        (0x4c8e068,0x4c8e0da),(0x4c8da4c,0x4c8da65),(0x3575254,0x357525c))
    return dict(schema='a7c2-ap-mpr-encoding-static/1',ap_sha256=AP_SHA,
        wrapper='0x3574174',parameter_base='x29 +0x300',
        parameter_offsets={'0x178':'codec profile enum','0x17c':'quality enum; bitrate not verified',
            '0x180':'frame-rate enum'},
        library_call='0x3575258 -> PLT 0x16604c0',
        library_import=imported_slots(elf,{0x5bc2a68}),
        ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(
            span(ap,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in spans],
        code_or_firmware_modified=False,camera_io=False,bitrate_verified=False,
        library_runtime_target_resolved=False,continuous_model_to_encoder_execution=False)


def run_original(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    result=[]
    for builder in run_builder(ap)['cases']:
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for page in (0x3574000,0x4c8e000,0x3559000,0x4c8d000):
            uc.mem_map(page,4096,u.UC_PROT_READ|(u.UC_PROT_EXEC if page in (0x3574000,0x3559000) else 0))
            uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
        stack,obj,fp=0x10000000,0x20000000,0x10000100
        uc.mem_map(stack,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(stack,b'\xa5'*4096)
        uc.mem_map(obj,4096,u.UC_PROT_READ);uc.mem_write(obj,b'\xa5'*4096)
        for off,value in ((0x10,builder['output_90']),(0x14,7),
            (0x20,builder['output_a0']),(0x24,builder['output_a4'])):
            uc.mem_write(obj+off,struct.pack('<I',value))
        uc.reg_write(a.UC_ARM64_REG_X28,obj);uc.reg_write(a.UC_ARM64_REG_X29,fp)
        path=[];phase=['conversion']
        def code(em,pc,size,_):
            ranges=((0x3574578,0x35745a4),(0x3574824,0x3574850),(0x35748d8,0x35748e8),
                (0x3574948,0x3574958),(0x3574a54,0x3574b58),(0x3574bec,0x3574bf4),
                (0x3574e0c,0x3574e44)) if phase[0]=='conversion' else ((0x3559834,0x3559990),)
            if size!=4 or not any(lo<=pc<hi for lo,hi in ranges):raise ValueError(f"Unreviewed MPR conversion instruction {pc:#x}.")
            path.append(pc)
        def memory(em,access,addr,size,value,_):
            if access==u.UC_MEM_WRITE:
                allowed=addr in (fp+0x478,fp+0x47c,fp+0x480) and size==4
            else:
                allowed=(addr in (obj+0x10,obj+0x14,obj+0x20,obj+0x24) and size==4)
                allowed |= any(lo<=addr and addr+size<=hi for lo,hi in
                    ((0x4c8e068,0x4c8e0da),(0x4c8da4c,0x4c8da65)))
            if not allowed:raise ValueError('Unreviewed MPR conversion memory.')
        uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(0x3574578,0x3574bf4,count=200,timeout=1_000_000)
        if uc.reg_read(a.UC_ARM64_REG_PC)!=0x3574bf4:raise ValueError('MPR conversion did not stop before remaining helpers.')
        profile,quality,rate=struct.unpack('<III',uc.mem_read(fp+0x478,12))
        names=[];phase[0]='naming'
        for entry,value in ((0x3559834,profile),(0x3559904,rate)):
            uc.reg_write(a.UC_ARM64_REG_X0,value);uc.reg_write(a.UC_ARM64_REG_X1,0x21000000)
            uc.emu_start(entry,0x3559768,count=50,timeout=1_000_000)
            if uc.reg_read(a.UC_ARM64_REG_PC)!=0x3559768:raise ValueError('MPR naming did not reach string-copy boundary.')
            va=uc.reg_read(a.UC_ARM64_REG_X1);raw=span(ap,elf.file_offset(va,90),90).split(b'\0')[0]
            names.append(dict(string_va=hex(va),text=raw.decode('ascii'),sha256=hashlib.sha256(raw+b'\0').hexdigest()))
        expected_profile='VPC_AVC_3840x2160_'+('422_10BIT_LONG' if builder['output_a4'] else '420_8BIT_LONG')
        expected_rate={20:'FRAME_RATE_59_94P',18:'FRAME_RATE_50P',15:'FRAME_RATE_29_97P'}[builder['output_90']]
        if [n['text'] for n in names]!=[expected_profile,expected_rate]:raise ValueError('Original MPR named outputs differ.')
        untouched=bytearray(uc.mem_read(stack,4096));untouched[0x578:0x584]=b'\xa5'*12
        if untouched!=b'\xa5'*4096:raise ValueError('MPR conversion canary changed.')
        result.append(dict(setting_rate=builder['rate'],quality_setting=builder['quality_setting'],
            profile_enum=profile,quality_enum=quality,rate_enum=rate,names=names,
            instruction_stream_sha256=hashlib.sha256(b''.join(span(ap,elf.file_offset(pc,4),4) for pc in path)).hexdigest()))
    return dict(schema='a7c2-ap-mpr-encoding-original/1',ap_sha256=AP_SHA,
        case_count=len(result),cases=result,fragments_executed_separately=True,
        original_builder_outputs_used=True,original_string_pointer_selection_executed=True,
        string_copy_executed=False,quality_bitrate_verified=False,encoder_called=False,
        camera_io=False,recording_verified=False,installable=False)
