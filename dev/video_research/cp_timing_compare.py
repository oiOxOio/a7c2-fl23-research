"""Original CP default-table timing arithmetic, without physical-unit claims.

Use original per-mode input records; never create an absent sensor mode or mark
a driver ready. Stop before rounding/downstream helpers. VFP is enabled only in
the isolated emulator, not asserted as a captured camera execution state.
"""
from __future__ import annotations
import hashlib
import math
import struct
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span
from cp_availability_init import TABLE_FIELDS
MODE_IDS=0xde99d4
REQUEST_TABLE=0xdea154
META_TABLE=0xde9ca4
CLOCK_RECORD=0xee01d2


def inspect(cp: bytes) -> dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    if (TABLE_FIELDS[0x2c],TABLE_FIELDS[0x24],TABLE_FIELDS[0x18])!=(REQUEST_TABLE,META_TABLE,CLOCK_RECORD):
        raise ValueError('Original table coordinate mismatch.')
    ranges=((0x98d8ce,0x98d912),(0x98df2c,0x98df72),(0x39c468,0x39c486),
        (0x13195a,0x13197e),(0x1314a0,0x1314c6),(0x1315cc,0x1315d0),
        (0x13164c,0x131678),(0x98deb4,0x98df2c),(0x131710,0x131718),(0x98d2b6,0x98d35a),
        (0x98d37c,0x98d3da),(0x98d3da,0x98d4e2),
        (0x398f70,0x398fea),(0x98b128,0x98b134),(0x510800,0x510830),
        (0x55c024,0x55c0dc),(0xbe9130,0xbe9192),(0xbe9d98,0xbe9eec),
        (0xc2f2ac,0xc2f2b4),(0x10fd874,0x10fd8b0),
        (0x989d8c,0x989db8),(0x98d35a,0x98d3da),(0xde98c8,0xde98d4),
        (0x335160,0x3351ce),(0x335252,0x33527a),(0x32f9f0,0x32fa54),
        (0x348bcc,0x348d32))
    return dict(schema='a7c2-cp-default-timing-static/1',cp_sha256=CP_SHA,
        default_selection='table object +0xc = 0 from original constructor; index selects +0x2c',
        per_mode_loop='0x98d8ea..0x98d900 loads table +0x2c with 24-byte stride into r2; virtual +0x10 dispatch',
        request_table=hex(REQUEST_TABLE),request_stride=24,
        metadata_table=hex(META_TABLE),metadata_stride=28,shared_record=hex(CLOCK_RECORD),
        quantity_formula='original fractional-period helper result * request_word_at_4 * metadata_u16_at_8 * 256',
        destination='helper 0x131490 output +0x20, after unexecuted rounding helper 0x14f078',
        downstream_transfer=dict(
            get_param='0x989d8c -> primary vtable +0x28 -> 0x98d35a; virtual +0x30 -> 0x98d37c',
            vtable_entries={hex(k):hex(struct.unpack('<I',cp_span(cp,0xde98a0+k,4))[0]) for k in (0x28,0x2c,0x30)},
            record_copy='0x98d36a..0x98d370 passes computed record and 0x170 size to original memcpy',
            consumer='0x335160; diagnostic source Set/EC_SetExtInfoSubFunc.cpp at 0xf78c6f',
            success_branch='0x335252..0x33526a copies 64 bytes from retrieved record +0xb0 to output +0x80',
            quantity_coordinates='computed record +0xd0 -> exposure-info output +0xa0',
            caller='0x32fa02 supplies stack+0x48 output; successful branch 0x32fa52 passes same output to 0x348bcc',
            remaining_gap='The copy establishes transfer, not subsequent use of output +0xa0 as a hardware frame-period register.',
            full_call_chain_executed=False,hardware_timing_consumer_verified=False,
            physical_unit_verified=False),
        original_scale=struct.unpack('<d',cp_span(cp,0x131710,8))[0],
        lower_resolution_candidate=dict(
            mode_id='0x5002',index=5,
            frame_table='0xee01d6',frame_stride=38,
            frame_width=struct.unpack('<H',cp_span(cp,0xee01d6+5*38+8,2))[0],
            frame_height=struct.unpack('<H',cp_span(cp,0xee01d6+5*38+26,2))[0],
            comparison_mode='0xa000',comparison_index=7,
            comparison_width=struct.unpack('<H',cp_span(cp,0xee01d6+7*38+8,2))[0],
            comparison_height=struct.unpack('<H',cp_span(cp,0xee01d6+7*38+26,2))[0],
            conditional_16_9_geometry=dict(input_width=3504,input_height=1971,
                output_width=3840,output_height=2160,linear_scale_numerator=80,linear_scale_denominator=73,
                qualification='Arithmetic only, assuming centered same-aspect crop and uniform upscale; not a verified ISP path.'),
            full_sensor_field_of_view_verified=False,binning_or_line_skip_verified=False,
            actual_4k_output_from_this_mode_verified=False,native_4k_detail_verified=False),
        ranges=[dict(va=hex(lo),end_exclusive=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest())
                for lo,hi in ranges],
        conditional_override=dict(
            entry='0x98d2b6; 0x98d37c invokes it at 0x98d3a0 before obtaining computed output',
            source_base='0x1211040',records=2,record_stride=10,
            match='source +0xd4 +slot*10 u16 equals table mode ID at selected index',
            replacement_fields=[dict(source_offset=hex(src),request_offset=hex(dst),source_width=width)
                for src,dst,width in ((0xd0,0,2),(0xd2,4,2),(0xd6,8,1),(0xd7,9,1),(0xd8,10,1))],
            action='copies original 24-byte request via virtual +0x20, replaces matched fields, then invokes virtual +0x10 at 0x98d33e',
            alternate_entry='0x98d3da accepts caller request and applies same two conditional overrides at 0x98d45a..0x98d490 before virtual +0xc',
            original_file_record_sha256=hashlib.sha256(cp_span(cp,0x1211110,20)).hexdigest(),
            original_file_records_all_zero=not any(cp_span(cp,0x1211110,20)),
            shadow_binding=dict(
                original_rows=[dict(property_id=hex(struct.unpack('<I',cp_span(cp,0x10fd874+i*4,4))[0]),
                    destination=hex(struct.unpack('<I',cp_span(cp,0x10fd888+i*4,4))[0]),
                    size=struct.unpack('<I',cp_span(cp,0x10fd89c+i*4,4))[0]) for i in range(4)],
                diagnostic='cam_imager_senser_copy_bk2shadow at 0x398fec',
                initialization='0x398fde -> 0x510800 -> 0x55c024 -> 0xbe9130; actual property metadata/backing pointer required',
                initial_copy='0xbe9174 gets source via 0xbe9990; 0xbe917e copies to table destination',
                registration='0x398fa4..0x398fb2 associates property ID, callback 0x98b129, destination',
                event='0xbe9e0c checks event ID against registration; 0xbe9e84 invokes callback with size, source, destination',
                callback='0x98b128 moves arguments to destination/source/size; Thumb 0xc2f2ac interworks to ARM 0xc2f2b0 branch to 0x61e60c memcpy',
                storage_loaded_or_event_dispatched=False,source_values_verified=False,
                qualification='Static binding is not a captured value, a user-menu link or authorization to modify the property.'),
            live_values_or_writers_verified=False,override_executed=False,
            caution='File zeros do not establish loaded/runtime state, ownership, disabled overrides or write authorization.'),
        runtime_table_selection_verified=False,physical_unit_verified=False,
        actual_frame_cadence_verified=False,camera_io=False,installable=False)


def _run_mode_cases(cp: bytes, modes: tuple[tuple[int, int], ...]) -> list[dict]:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for index,mode in modes:
        if struct.unpack('<I',cp_span(cp,MODE_IDS+index*4,4))[0]!=mode:raise ValueError('Original mode index differs.')
        req,meta=REQUEST_TABLE+index*24,META_TABLE+index*28
        uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
        for page in (0x98d000,0x131000,0xdea000,0xde9000,0xee0000):
            uc.mem_map(page,4096,u.UC_PROT_READ|(u.UC_PROT_EXEC if page in (0x98d000,0x131000) else 0))
            uc.mem_write(page,cp_span(cp,page,4096))
        uc.reg_write(a.UC_ARM_REG_C1_C0_2,0xf00000)
        uc.reg_write(a.UC_ARM_REG_FPEXC,0x40000000)
        uc.reg_write(a.UC_ARM_REG_R0,req);uc.reg_write(a.UC_ARM_REG_R1,CLOCK_RECORD)
        uc.reg_write(a.UC_ARM_REG_LR,0x30000001)
        trace=[]
        def code(em,pc,size,_):
            if not any(lo<=pc and pc+size<=hi for lo,hi in ((0x98deb4,0x98df2c),
                (0x1314be,0x1314c6),(0x1315cc,0x1315d0),(0x13164c,0x131668))):
                raise ValueError('Unreviewed timing instruction.')
            trace.append((pc,size))
        def memory(em,access,addr,size,value,_):
            if access!=u.UC_MEM_READ or not any(lo<=addr and addr+size<=hi for lo,hi in
                ((req,req+12),(meta+8,meta+10),(CLOCK_RECORD+2,CLOCK_RECORD+4),(0x131710,0x131718),(0x98d2b6,0x98d35a),
        (0x98d37c,0x98d3da),(0x98d3da,0x98d4e2),
        (0x398f70,0x398fea),(0x98b128,0x98b134),(0x510800,0x510830),
        (0x55c024,0x55c0dc),(0xbe9130,0xbe9192),(0xbe9d98,0xbe9eec),
        (0xc2f2ac,0xc2f2b4),(0x10fd874,0x10fd8b0),
        (0x989d8c,0x989db8),(0x98d35a,0x98d3da),(0xde98c8,0xde98d4),
        (0x335160,0x3351ce),(0x335252,0x33527a),(0x32f9f0,0x32fa54),
        (0x348bcc,0x348d32))):
                raise ValueError('Unexpected timing memory access.')
        uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
        def execute(start,end,bound):
            uc.emu_start(start|1,end,count=bound,timeout=1_000_000)
            if uc.reg_read(a.UC_ARM_REG_PC)!=end:raise ValueError('Timing fragment missed stop boundary.')
        execute(0x98deb4,0x30000000,64)
        def returned_double():return struct.unpack('<d',struct.pack('<II',uc.reg_read(a.UC_ARM_REG_R0),uc.reg_read(a.UC_ARM_REG_R1)))[0]
        period=returned_double()
        # Original instructions preserve helper output into D8 and load original scale into D9.
        execute(0x1314be,0x1314c6,2)
        uc.reg_write(a.UC_ARM_REG_R8,req);execute(0x1315cc,0x1315d0,1)
        uc.reg_write(a.UC_ARM_REG_R9,meta);execute(0x13164c,0x131668,16)
        quantity=returned_double()
        count=struct.unpack('<I',cp_span(cp,req+4,4))[0]
        multiplier=struct.unpack('<H',cp_span(cp,meta+8,2))[0]
        if not math.isfinite(quantity) or not math.isclose(quantity,period*count*multiplier*256,rel_tol=1e-14):
            raise ValueError('Timing quantity differs from original operands.')
        cases.append(dict(mode=hex(mode),index=index,request_va=hex(req),metadata_va=hex(meta),
            request_count=count,mode_multiplier=multiplier,original_scale=256,
            helper_result=period,pre_rounding_quantity=quantity,
            request_record_sha256=hashlib.sha256(cp_span(cp,req,24)).hexdigest(),
            metadata_record_sha256=hashlib.sha256(cp_span(cp,meta,28)).hexdigest(),
            instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest()))
    return cases


def run_original(cp: bytes) -> dict:
    cases = _run_mode_cases(cp, ((9,0x880),(23,0x821),(5,0x5002)))
    ratio=cases[0]['pre_rounding_quantity']/cases[1]['pre_rounding_quantity']
    if not math.isclose(ratio,2.0,rel_tol=1e-14):raise ValueError('Original timing ratio differs.')
    return dict(schema='a7c2-cp-default-timing-original/1',cp_sha256=CP_SHA,cases=cases,
        quantity_ratio_0880_over_0821=ratio,
        quantity_ratio_5002_over_0821=cases[2]['pre_rounding_quantity']/cases[1]['pre_rounding_quantity'],
        original_table_inputs=True,
        helper_and_arithmetic_fragments_separate=True,emulator_vfp_enabled=True,
        source_of_vfp_input='original memory and helper output; no host arithmetic result injected',
        stopped_before='0x131668 calls rounding helper 0x14f078',
        rounding_or_downstream_helpers_executed=False,
        inference='The 2:1 default quantity ratio is consistent with the separately proven lower-rate versus 59.94P branches; it is not a measured sensor cadence.',
        physical_unit_verified=False,actual_frame_cadence_verified=False,
        runtime_override_excluded=False,driver_readiness_fabricated=False,camera_io=False,installable=False)


def run_catalog(cp: bytes) -> dict:
    """Compare every original default mode; no frame-rate or full-FOV inference.

    Each case uses the same bounded original helper/arithmetic fragments as
    run_original. No whole-firmware execution, runtime override, queue operation,
    readout/scaler change or sensor-register write is performed.
    """
    from src.video_research.reference import MODE_IDS, FRAME_TABLE_VA, FRAME_STRIDE
    cases = _run_mode_cases(cp, tuple(enumerate(MODE_IDS)))
    by_mode = {int(case['mode'], 16): case for case in cases}
    reference = by_mode[0x0821]['pre_rounding_quantity']
    if reference <= 0 or not math.isfinite(reference):
        raise ValueError('Invalid comparison quantity.')
    for case in cases:
        row = FRAME_TABLE_VA + case['index'] * FRAME_STRIDE
        case['frame_width'] = struct.unpack('<H', cp_span(cp, row + 8, 2))[0]
        case['frame_height'] = struct.unpack('<H', cp_span(cp, row + 0x1a, 2))[0]
        case['frame_record_sha256'] = hashlib.sha256(cp_span(cp, row, FRAME_STRIDE)).hexdigest()
        case['quantity_ratio_to_0821'] = case['pre_rounding_quantity'] / reference
    return dict(schema='a7c2-cp-default-timing-catalog-original/1', cp_sha256=CP_SHA,
        case_count=len(cases), cases=cases, reference_mode='0x821',
        reference_quantity=reference,
        original_table_inputs=True, all_original_default_mode_rows_compared=True,
        original_helper_and_arithmetic_fragments_separate=True,
        emulator_vfp_enabled=True,
        stopped_before='0x131668 calls rounding helper 0x14f078',
        qualification='Complete for the 30 pinned default-table rows only. Dimensions are stored metadata; quantities are pre-rounding arithmetic, not measured frame periods. This does not enumerate every possible firmware or hardware configuration.',
        rounding_or_downstream_helpers_executed=False, physical_unit_verified=False,
        actual_frame_cadence_verified=False, full_sensor_field_of_view_verified=False,
        binning_or_line_skip_verified=False, runtime_override_excluded=False,
        sensor_to_encoder_path_verified=False, hardware_impossibility_proven=False,
        driver_readiness_fabricated=False, camera_io=False, installable=False)
