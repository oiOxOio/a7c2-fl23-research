"""Original MPR parameter builder under explicit synthetic AP model state.

Quality enums are NOT bitrates. This does not send MPR requests, initialize the
encoder, set the sensor, or demonstrate physical recording.
"""
from __future__ import annotations
import hashlib
import struct
from request_trace import AP_SIZE, AP_SHA, Elf64, check_image, span
from ap_xrefs import pc_address, add_immediate

ENTRY = 0x3204758
RETURN = 0x32060c8


def getter_state(elf: Elf64, getter: int) -> int:
    words = struct.unpack('<5I', span(elf.data, elf.file_offset(getter,20),20))
    first=pc_address(words[0],getter)
    if first is None or first[:2] != ('adrp',0) or words[4] != 0xd65f03c0:
        raise ValueError('Expected original pure AP state getter.')
    value=first[2]
    for word in words[1:4]:
        add=add_immediate(word)
        if add is None or add[:2] != (0,0):raise ValueError('Unexpected getter operation.')
        value+=add[2]
    return value


def model_getters(elf: Elf64) -> list[int]:
    result={0x286608c,0x287a4d0}
    for pc in range(0x3204778,0x3204ae8,4):
        word=struct.unpack('<I',span(elf.data,elf.file_offset(pc,4),4))[0]
        if word>>26 == 0b100101:
            delta=word&0x3ffffff
            if delta&0x2000000:delta-=0x4000000
            target=pc+delta*4
            if 0x2860000<=target<0x2870000:result.add(target)
    return sorted(result)


def inspect(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    ranges=((ENTRY,0x3204b30),(0x3204e74,0x3204f4c),(0x3206a00,0x3206be4),
        (0x32093a8,0x32093cc),(0x3209464,0x320948c),(0x4c2c014,0x4c2c01b),
        (0x4c2c16c,0x4c2c17c),(0x4c2c18c,0x4c2c19a),(0x3107db8,0x3107de8),(0x32099bc,0x3209a24),
        (0x34591bc,0x34591d8),(0x34d4188,0x34d41c8))
    return dict(schema='a7c2-ap-mpr-quality-static/1',ap_sha256=AP_SHA,
        builder=hex(ENTRY),diagnostic='0x4c2eb50',
        diagnostic_type='sequence_set_movie_rec_param_meta::scoped_read_model',
        exposure_predicate=dict(function='0x2d464e4',diagnostic='0x4b85cd0',
            diagnostic_name='is_movie_exposure_mode'),
        getters={hex(g):hex(getter_state(elf,g)) for g in model_getters(elf)},
        selected_inputs={'format':'0x286608c','rate':'0x286612c',
            'rate_0_1_quality':'0x28662bc','rate_2_quality':'0x28662e4','exposure':'0x287a4d0'},
        output_offsets=['0x90','0xa0','0xa4'],
        static_receiver_coordinates=dict(sequence_constructor='0x32099e8',
            builder_receiver='sequence +0x18; set at 0x3209a0c',
            builder_tail_call='0x32099e4 -> 0x3204758',
            vtable_got='0x5b7c9d0',vtable_relocation_addend='0x5b43a60',
            callback_slot='0x5b43a80',callback='0x34591bc',
            wrapper_input='sequence +0x98 at 0x34591c0 = builder +0x80',
            wrapper='0x34d4188 -> 0x3574174',
            output_to_input={'0x90':'0x10','0xa0':'0x20','0xa4':'0x24'},
            lock_helpers_executed=False,runtime_virtual_dispatch_verified=False),
        ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(
            span(ap,elf.file_offset(lo,hi-lo),hi-lo)).hexdigest()) for lo,hi in ranges],
        caveat='Numeric quality/color-space outputs are not identified as measured or target bitrates.',
        unresolved=['caller scheduling','quality enums to encoder bitrate/chroma parameters',
            'MPR delivery','joint sensor/encoder capability and actual recording'],
        camera_io=False,recording_verified=False,installable=False)


def run_original(ap: bytes) -> dict:
    check_image(ap,AP_SIZE,AP_SHA,'AP');elf=Elf64(ap)
    import unicorn as u
    from unicorn import arm64_const as a
    states={g:getter_state(elf,g) for g in model_getters(elf)}
    pages=(0x2866000,0x286a000,0x287a000,0x2d46000,0x3107000,0x4c2c000,
        *range(0x3204000,0x320a000,4096))
    cases=[]
    fixtures=((0,8,20,18,1),(0,13,20,16,0),(1,8,18,18,1),
        (2,14,15,15,1),(2,18,15,13,0),(2,22,15,9,0))
    for rate,quality,expected_rate,expected_quality,expected_color in fixtures:
        uc=u.Uc(u.UC_ARCH_ARM64,u.UC_MODE_ARM)
        for page in pages:
            uc.mem_map(page,4096,u.UC_PROT_READ|(0 if page==0x4c2c000 else u.UC_PROT_EXEC))
            uc.mem_write(page,span(ap,elf.file_offset(page,4096),4096))
        for page in sorted({s&~4095 for s in states.values()}):
            uc.mem_map(page,4096,u.UC_PROT_READ);uc.mem_write(page,b'\xa5'*4096)
        for addr in states.values():uc.mem_write(addr,struct.pack('<I',0))
        declared={0x286608c:7,0x286612c:rate,0x28662bc:quality,0x28662e4:quality,0x287a4d0:12}
        for getter,value in declared.items():uc.mem_write(states[getter],struct.pack('<I',value))
        stack,obj,sp=0x10000000,0x20000000,0x10000800
        for page in (stack,obj):
            uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_WRITE);uc.mem_write(page,b'\xa5'*4096)
        for reg,value in ((a.UC_ARM64_REG_SP,sp),(a.UC_ARM64_REG_X0,obj),(a.UC_ARM64_REG_LR,0xdead0000)):
            uc.reg_write(reg,value)
        path=[];writes=[];reads=set()
        def code(em,pc,size,_):
            if size!=4:raise ValueError('Unexpected MPR instruction width.')
            allowed=any(lo<=pc<hi for lo,hi in ((ENTRY,0x3204af4),
                (0x3204e74,0x3204ec0),(0x3204f1c,0x3204f34),
                (0x32060b0,0x32060cc),(0x3206a00,0x3206adc),
                (0x32093a8,0x32093cc),(0x3209464,0x320948c),
                (0x3107db8,0x3107de8),(0x2d464e4,0x2d4651c),(0x2d465cc,0x2d465d0)))
            allowed |= any(g<=pc<g+20 for g in states)
            if not allowed:raise ValueError(f'Unreviewed MPR execution at {pc:#x}.')
            path.append(pc)
        def memory(em,access,addr,size,value,_):
            allowed=sp-0x100<=addr and addr+size<=sp
            if access==u.UC_MEM_READ:
                allowed |= (addr in states.values() and size==4)
                allowed |= 0x4c2c000<=addr and addr+size<=0x4c2d000
                if addr in states.values():reads.add(addr)
            else:
                allowed |= (addr==obj+0x90 and size==4) or (obj+0xa0<=addr and addr+size<=obj+0xa8)
                if obj<=addr<obj+4096:writes.append((addr-obj,size))
            if not allowed:raise ValueError(f'Unreviewed MPR memory at {addr:#x}.')
        uc.hook_add(u.UC_HOOK_CODE,code)
        uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        uc.emu_start(ENTRY,0xdead0000,count=2000,timeout=1_000_000)
        got=tuple(struct.unpack('<I',uc.mem_read(obj+off,4))[0] for off in (0x90,0xa0,0xa4))
        expected=(expected_rate,expected_quality,expected_color)
        if got!=expected or path[-1]!=RETURN or uc.reg_read(a.UC_ARM64_REG_SP)!=sp:
            raise ValueError('Original MPR builder result/return mismatch.')
        untouched=bytearray(uc.mem_read(obj,4096))
        for off in (0x90,0xa0,0xa4):untouched[off:off+4]=b'\xa5'*4
        if untouched!=b'\xa5'*4096:raise ValueError('MPR output canary changed.')
        for lo,hi in ((stack,sp-0x100),(sp,stack+4096)):
            if bytes(uc.mem_read(lo,hi-lo))!=b'\xa5'*(hi-lo):raise ValueError('MPR stack canary changed.')
        cases.append(dict(format=7,exposure=12,rate=rate,quality_setting=quality,
            output_90=got[0],output_a0=got[1],output_a4=got[2],
            instruction_count=len(path),instruction_stream_sha256=hashlib.sha256(b''.join(
                span(ap,elf.file_offset(pc,4),4) for pc in path)).hexdigest(),
            read_model_states=[hex(s) for s in sorted(reads)],output_writes=writes))
    return dict(schema='a7c2-ap-mpr-quality-original/1',ap_sha256=AP_SHA,
        case_count=len(cases),cases=cases,synthetic_model_state=True,
        all_unselected_getter_values=0,entire_builder_executed=True,original_getters_executed=True,
        unknown_helpers_executed=0,helpers_stubbed=False,encoder_request_sent=False,
        numeric_bitrate_verified=False,physical_recording_verified=False,camera_io=False,installable=False)
