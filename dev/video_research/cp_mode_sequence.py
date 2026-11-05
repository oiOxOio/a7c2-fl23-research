"""Read-only original mode-sequencer table provenance, not movie enum names."""
from __future__ import annotations
import hashlib
import struct
from request_trace import CP_SIZE, CP_SHA, check_image, cp_span

TABLE = 0xd96410
STATIC_COUNT = 246


def phase_words(words: tuple[int, ...]) -> list[dict]:
    """Decode writes before the first high-bit phase marker, without running it."""
    result = []
    for word in words:
        if type(word) is not int or not 0 <= word <= 0xffff:
            raise ValueError('Expected uint16 sequence word.')
        if word & 0x8000:
            return result
        field = word >> 8
        if not 1 <= field <= 13:
            raise ValueError('Sequence write outside reviewed field range.')
        result.append(dict(field_index=field-1, object_offset=hex(0x16+2*field),
                           stored_word=hex(word), descriptor_index=word & 255))
    raise ValueError('Missing phase marker within declared sequence.')


def inspect(cp: bytes) -> dict:
    check_image(cp, CP_SIZE, CP_SHA, 'CP')
    rows = []
    for index in range(STATIC_COUNT):
        raw = cp_span(cp,TABLE+index*16,16)
        source,target,sequence,count = struct.unpack('<4I',raw)
        if not 1 <= count <= 1024:
            raise ValueError('Unreviewed original sequence count.')
        words = struct.unpack('<'+'H'*count,cp_span(cp,sequence,count*2))
        writes = phase_words(words)
        rows.append(dict(index=index,record_va=hex(TABLE+index*16),source_state=source,
            target_state=target,sequence_va=hex(sequence),word_count=count,
            record_sha256=hashlib.sha256(raw).hexdigest(),
            sequence_sha256=hashlib.sha256(cp_span(cp,sequence,count*2)).hexdigest(),
            first_phase_writes=writes))
    # One declared configuration index, not a recovered live property value.
    raw = cp_span(cp,0xd94790,16)
    source,target,sequence,count=struct.unpack('<4I',raw)
    words=struct.unpack('<'+'H'*count,cp_span(cp,sequence,count*2))
    phases=[];begin=0
    for end,word in enumerate(words):
        if word&0x8000:
            writes=phase_words(words[begin:end+1])
            phases.append(dict(index=len(phases),start_word=begin,marker_word=end,
                selector_writes=[w['descriptor_index'] for w in writes if w['field_index']==0]))
            begin=end+1
    if begin!=count:raise ValueError('Generated sequence lacks final marker.')
    return dict(schema='a7c2-cp-mode-sequence-static/1',cp_sha256=CP_SHA,
        static_records=STATIC_COUNT,runtime_records=308,
        generated_example=dict(callback_slot='0xd97374',callback='0x8dc6ec',
            configuration_input='initializer property 0x300a5; getter reads argument +0',
            declared_configuration_index=0,configuration_index_validity_verified=False,
            table_base='0xd94790',record_sha256=hashlib.sha256(raw).hexdigest(),
            source_state=source,target_state=target,sequence_va=hex(sequence),word_count=count,
            sequence_sha256=hashlib.sha256(cp_span(cp,sequence,count*2)).hexdigest(),phases=phases,
            caution='Descriptor 6 is a phase value here, not a stable movie enum or 4K60 label.'),
        static_copy=dict(at='0x36695c..0x366982',source=hex(TABLE),destination='0x1870468',bytes=0xf60),
        dynamic_records=dict(count=62,callback_table='0xd97370',loop='0x366998..0x3669b4',configuration_inputs_verified=False),
        initialization=dict(at='0xb1ef5a..0xb1ef72',table_getter='0x8dcd60',count_getter='0x8dcd6a',object='0x1a52a88'),
        record_consumer=dict(at='0xb1f35a',stride=16,key_fields=[0,4],sequence_field=8,count_field=12),
        phase_consumer=dict(at='0xb1f3ae',word_index_field='0x14',sequence_pointer_field='0xc',
            write_offset='0x16 + 2 * (word >> 8)',stops_on='word bit 15; marker is not stored'),
        getter_to_snapshot=dict(getter='0xb1f1a0 -> 0xb1f3ce',index=0,source='0x1a52aa0',
            call='0x4d7bca',store='0x4d7bd6',destination='0x172fe54',
            retained_previous_value_path='0x4d7b58..0x4d7b62; branch conditions unresolved'),
        example_rows=[rows[i] for i in (0,6,8,11)],
        table_sha256=hashlib.sha256(cp_span(cp,TABLE,STATIC_COUNT*16)).hexdigest(),
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
            for lo,hi in ((0x36695c,0x3669b6),(0xb1ef5a,0xb1ef76),(0xb1f35a,0xb1f3d6),
                          (0xb1f1a0,0xb1f1ae),(0x4d7bc8,0x4d7bda),(0x8dc6ec,0x8dc708))],
        runtime_transition_selection_verified=False,mode_enum_names_verified=False,
        movie_to_sensor_selection_verified=False,camera_io=False,installable=False)


def run_original(cp: bytes) -> dict:
    """Execute original first-phase updater with selected original table rows."""
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for index in (0,6,8,11):
        source,target,seq,count=struct.unpack('<4I',cp_span(cp,TABLE+index*16,16))
        words=struct.unpack('<'+'H'*count,cp_span(cp,seq,count*2))
        writes=phase_words(words)
        em=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        for page in {0xb1f000,seq&~4095,(seq+count*2-1)&~4095}:
            em.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);em.mem_write(page,cp_span(cp,page,4096))
        obj,sentinel=0x21000000,0x22000000
        em.mem_map(obj,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
        initial=bytearray(b'\xa5'*4096);struct.pack_into('<I',initial,12,seq);struct.pack_into('<I',initial,20,0)
        em.mem_write(obj,bytes(initial));em.mem_map(sentinel,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
        em.reg_write(a.UC_ARM_REG_R0,obj);em.reg_write(a.UC_ARM_REG_LR,sentinel|1)
        trace=[];stopped=[]
        def instruction(vm,addr,size,_):
            if addr==sentinel:stopped.append(addr);vm.emu_stop();return
            if not 0xb1f3ae<=addr or addr+size>0xb1f3ce:raise ValueError('Unreviewed sequencer instruction.')
            trace.append((addr,size))
        allowed_writes={(obj+20,4)}|{(obj+int(w['object_offset'],16),2) for w in writes}
        def memory(vm,access,addr,size,value,_):
            if access==u.UC_MEM_WRITE:
                if (addr,size) not in allowed_writes:raise ValueError('Unexpected sequence write.')
            elif not ((addr,size) in {(obj+12,4),(obj+20,4)} or seq<=addr and addr+size<=seq+count*2):
                raise ValueError('Unexpected sequence read.')
        em.hook_add(u.UC_HOOK_CODE,instruction);em.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        em.emu_start(0xb1f3af,0,count=1000,timeout=1_000_000)
        expected=bytearray(initial);struct.pack_into('<I',expected,20,len(writes))
        for w in writes:struct.pack_into('<H',expected,int(w['object_offset'],16),int(w['stored_word'],16))
        if stopped!=[sentinel] or bytes(em.mem_read(obj,4096))!=expected:raise ValueError('Original phase differs from bounded decode.')
        cases.append(dict(row=index,source_state=source,target_state=target,writes=len(writes),
            next_word_index=len(writes),runtime_selection_verified=False,
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,x,n) for x,n in trace)).hexdigest()))
    return dict(schema='a7c2-cp-mode-sequence-fragments/1',cp_sha256=CP_SHA,cases=cases,
        synthetic_initial_object=True,original_sequence_data=True,unknown_helpers_executed=0,
        subsequent_phase_execution_verified=False,mode_enum_names_verified=False,
        movie_to_sensor_selection_verified=False,camera_io=False,installable=False)
