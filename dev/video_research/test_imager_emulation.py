"""Identity guards without dependencies; optional original-instruction integration."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import ap_builder_emulation as ap
import ap_registration as registration
import ap_setting_flow as setting_flow
import ap_apsc_flow as apsc
import movie_setting_flow as movie
import ap_mpr_quality as mpr_quality
import ap_mpr_encoding as mpr_encoding
import avbbc_receiver
import mpr_bitrate
import mpr_codec_transport as codec_transport
import cp_availability_init as availability_init
import cp_timing_compare as timing_compare
import cp_request_handoff as handoff
import cp_lowres_route as lowres
import cp_stream_geometry as geometry
import cp_movie_geometry as movie_geometry
import cp_movie_selector as movie_selector
import cp_selector_fields as selector_fields
import cp_mode_sequence as mode_sequence
import cp_selector_state as selector_state
import cp_dispatch_emulation as dispatch
import cp_imager_emulation as handler
import cp_check_emulation as check
import cp_snapshot_emulation as snapshot
import osal_transport

class IdentityTests(unittest.TestCase):
    def test_timing_catalog_identity_before_emulator_import(self):
        with patch.dict(sys.modules, {'unicorn': None}):
            with self.assertRaises(ValueError):timing_compare.run_catalog(b'not firmware')

    def test_codec_transport_identity(self):
        for fn in (codec_transport.inspect,codec_transport.run_original):
            with self.assertRaises(ValueError):fn(b'bad')

    def test_geometry_lookup_identity(self):
        with self.assertRaises(ValueError):geometry.run_geometry_lookup(b'bad')

    def test_handoff_identity(self):
        for fn in (handoff.inspect,handoff.run_copies,handoff.run_queue_dispatch,handoff.run_stage_receiver,handoff.run_builder_gate):
            with self.assertRaises(ValueError):fn(b'bad')

    def test_mpr_quality_identity(self):
        for fn in (mpr_quality.inspect,mpr_quality.run_original,mpr_encoding.inspect,mpr_encoding.run_original,mpr_bitrate.inspect,mpr_bitrate.run_original):
            with self.assertRaises(ValueError):fn(b"bad")

    def test_sequence_phase_bounds(self):
        self.assertEqual(mode_sequence.phase_words((0x107,0x8000,0x100))[0]['object_offset'],'0x18')
        self.assertEqual(mode_sequence.phase_words((0x8000,)),[])
        for values in ((),(0x107,),(0,0x8000),(0xe00,0x8000),(-1,),(65536,),(True,)):
            with self.subTest(values=values),self.assertRaises(ValueError):mode_sequence.phase_words(values)
        with self.assertRaises(ValueError):mode_sequence.inspect(b'bad')

    def test_movie_identity_before_execution(self):
        with patch.object(movie,'Elf64') as parse:
            with self.assertRaises(ValueError):movie.inspect(b'bad',b'bad')
            with self.assertRaises(ValueError):movie.run_ap_original(b'bad')
            parse.assert_not_called()
        with self.assertRaises(ValueError):movie.run_cp_original(b'bad')

    def test_registration_identity_and_name_index(self):
        with patch.object(registration,'Elf64') as parse:
            with self.assertRaises(ValueError):registration.inspect(b'not firmware')
            parse.assert_not_called()
        with self.assertRaises(ValueError):registration.run_rate_original(b'not firmware')
        for index in (-1,65536,True):
            with self.assertRaises(ValueError):registration.name_at(None,index)

    def test_lifecycle_identity(self):
        with self.assertRaises(ValueError):dispatch.run_state_lifecycle_original(b'not firmware')

    def test_osal_identity_before_elf_parse(self):
        with patch.object(osal_transport,'Elf64') as parse:
            with self.assertRaises(ValueError):osal_transport.inspect(b'not an OSAL library')
            parse.assert_not_called()

    def test_invalid_images_fail_before_emulator_import(self):
        for module in (ap, dispatch, handler, snapshot, check, registration, apsc, selector_state, mode_sequence, selector_fields, movie_selector, availability_init, timing_compare, lowres, geometry, movie_geometry):
            with self.subTest(module=module.__name__), patch.dict(sys.modules, {'unicorn': None}):
                with self.assertRaises(ValueError):
                    module.run_original(b'not original firmware')

@unittest.skipUnless(os.environ.get('A7C2_VIDEO_CP_REFERENCE') and
    os.environ.get('A7C2_VIDEO_AP_REFERENCE') and importlib.util.find_spec('unicorn'),
    'Requires private original AP/CP and optional Unicorn.')
class OriginalInstructionTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('A7C2_VIDEO_AVBBC_REFERENCE'),'Requires private original libInfraAvbbc.so.')
    def test_original_avbbc_receiver(self):
        data=Path(os.environ['A7C2_VIDEO_AVBBC_REFERENCE']).read_bytes()
        static=avbbc_receiver.inspect(data)
        self.assertIs(static['receiver']['actual_delivery_verified'],False)
        topology=avbbc_receiver.inspect_ap_topology(Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes())
        self.assertEqual(topology['topology']['entry_index'],45)
        if os.environ.get('A7C2_VIDEO_MPR_REFERENCE'):
            pin=avbbc_receiver.run_profile_pin(Path(os.environ['A7C2_VIDEO_MPR_REFERENCE']).read_bytes(),data)
            self.assertEqual(pin['cases'][0],dict(profile=2,stream=0,codec_file_format=5,sdt_pin=3))
            self.assertIs(pin['continuous_setting_to_movie_record_proven'],False)
        self.assertIs(topology['osal_queue_consumer_identified'],False)
        self.assertEqual({v['target'] for v in static['virtual_bindings']},{'0xae75c','0xa41b0','0xa46e4'})
        if os.environ.get('A7C2_VIDEO_DATAFLOW_REFERENCE'):
            transport=avbbc_receiver.inspect_dataflow(Path(os.environ['A7C2_VIDEO_DATAFLOW_REFERENCE']).read_bytes())
            self.assertEqual({x['name'] for x in transport['imports']},{'osal_valloc_msg_wait','osal_snd_msg','osal_set_msg_src'})
            self.assertIs(transport['kernel_queue_route_verified'],False)
        if os.environ.get('A7C2_VIDEO_KERNEL_REFERENCE'):
            kernel=avbbc_receiver.inspect_kernel(Path(os.environ['A7C2_VIDEO_KERNEL_REFERENCE']).read_bytes())
            self.assertEqual(kernel['local_queue_index'],'0x0752')
            self.assertIs(kernel['kernel_loaded'],False)
        result=avbbc_receiver.run_original(data)
        self.assertEqual(result['routes'][0],dict(command=6,destination='0x80550122'))
        self.assertEqual([x['pin'] for x in result['pins']],[4,3,3,4,3,4])
        for flag in ('queue_operations_executed','virtual_dispatch_executed','pixel_buffers_executed','camera_io','installable'):
            self.assertIs(result[flag],False)

    @unittest.skipUnless(os.environ.get('A7C2_VIDEO_MPR_REFERENCE'),'Requires private original libmpr.so.')
    def test_original_codec_control_header_not_pixel_source(self):
        data=Path(os.environ['A7C2_VIDEO_MPR_REFERENCE']).read_bytes()
        report=codec_transport.run_original(data)
        self.assertEqual((report['source_setter_return'],report['source_setter_memory_accesses']),(0,0))
        self.assertEqual((report['encstart2_message_id'],report['command_id'],report['body_size']),('0x210',6,256))
        self.assertIs(report['transport_executed'],False)
        self.assertEqual(codec_transport.inspect(data)['transport']['destination'],'0x8055001f')

    def test_original_movie_stream_to_descriptor_geometry(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        r=movie_geometry.run_original(cp)
        self.assertEqual(r['descriptor_c0_to_c6'],[3840,2160,0x2345,0])
        self.assertEqual(r['copied_fields_1b4_to_1ba'][0],[3840,2160,3840,2160])
        self.assertIs(r['isp_calls_executed'],False)
        meta=movie_geometry.inspect(cp)
        self.assertIs(meta['encoder_buffer_identity_verified'],False)
        self.assertEqual(meta['lower_consumer_subsystem']['diagnostic'],'rcct_DistCorrectionCalcMulti')
        self.assertEqual([x['slot_28_target'] for x in meta['lower_consumer_subsystem']['static_singletons']],['0x544d9d','0x5459ed'])

    def test_original_geometry_lookup_and_conditional_clamp(self):
        r=geometry.run_geometry_lookup(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes())
        self.assertEqual([c['return_code'] for c in r['cases']],[0,11,11,0,11,11])
        for c in r['cases']:
            self.assertEqual(c['geometry'],[1024,682] if c['return_code']==0 else None)
            self.assertEqual(c['callback_4cd20d_conditional_clamp'],c['geometry'])
        self.assertIs(r['caller_flag_provenance_verified'],False)
        self.assertIs(r['conditional_4cd20d_clamp_executed'],True)

    def test_original_stage_geometry_branch_compatibility(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=geometry.run_original(cp)
        self.assertEqual(len(report['cases']),21)
        expected=[[1440,540],[1024,682],[720,480],[640,480],[1280,854],[1600,1066],[2048,1364]]
        for case in report['cases']:
            is_movie=case['callback']=='0x4c79c1'
            self.assertEqual(case['pre_clamp_dimensions'],[3840,2160] if is_movie else expected[case['declared_config_byte']])
            self.assertEqual(case['record_category'],0 if is_movie else 1)
            self.assertEqual(len(case['stream_fields_1b4_to_1ba']),0 if is_movie else 4)
        self.assertIs(report['later_clamp_executed'],False)
        self.assertIs(report['isp_executed'],False)
        self.assertIs(geometry.inspect(cp)['compatible_existing_4k_route_proven'],False)

    def test_original_lowres_route_not_movie_callback_assumption(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=lowres.run_original(cp)
        self.assertEqual([x['mode'] for x in report['cases']],['0x5002','0x5002','0x5004','0x5004'])
        self.assertEqual([x['callback'] for x in report['cases']],['0x4cd20d','0x4cc0a1']*2)
        self.assertFalse(report['availability_executed'])
        self.assertFalse(report['record_builder_executed'])
        static=lowres.inspect(cp)
        self.assertTrue(static['shared_sync_submission']['not_evidence_of_no_submission'])
        self.assertFalse(static['all_possible_routes_exhausted'])

    def test_original_movie_category_rejects_incompatible_route(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=handoff.run_builder_gate(cp)
        self.assertEqual([x['record_38'] for x in report['cases']],[0,1,1,1])
        self.assertTrue(report['default_movie_4de330_route_rejected'])
        self.assertFalse(report['preceding_selector_executed'])
        dag=handoff.inspect(cp)['gated_evidence_dag']
        self.assertEqual(dag[1]['status'],'rejected for default movie tuple')

    def test_original_stage_receiver_identity(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=handoff.run_stage_receiver(cp)
        self.assertTrue(report['init_receiver_equals_owner_word_zero'])
        self.assertTrue(report['main_callback_receives_owner'])
        self.assertFalse(report['actual_allocation_executed'])
        self.assertFalse(report['callback_bodies_executed'])
        self.assertEqual(report['instruction_stream_sha256'],'afbb346858908965d434a53303ca9cb824f336236171af9e88979d9adbbac304')
        self.assertTrue(handoff.inspect(cp)['sync_candidate']['static_receiver_identity_path_proven'])

    def test_original_queue_receiver_forwarding(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=handoff.run_queue_dispatch(cp)
        self.assertEqual([x['receiver_source'] for x in report['cases']],['node+0x1c'])
        self.assertEqual([x['callback_entry'] for x in report['cases']],['0x4ce7bc'])
        self.assertFalse(report['actual_receiver_alias_verified'])
        self.assertFalse(report['actual_callback_order_verified'])
        self.assertTrue(all(not x['callback_body_executed'] for x in report['cases']))

    def test_original_handoff_copies(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        static=handoff.inspect(cp)
        self.assertTrue(static['previous_request_generator_to_setmodeasync_claim_retracted'])
        self.assertFalse(static['sync_candidate']['receiver_alias_and_callback_lifecycle_verified'])
        result=handoff.run_copies(cp)
        self.assertEqual([x['mode_word'] for x in result['cases']],['0x821','0x821'])
        self.assertEqual([x['length'] for x in result['cases']],[0x304,0x304])
        self.assertEqual(result['instruction_stream_sha256'],'e394295773084077c01c4732991a8c3872564303ae44dbb641002ba657537265')
        self.assertFalse(result['setmode_sync_executed'])
        self.assertFalse(result['setmode_async_executed'])
        self.assertFalse(result['preceding_branch_gates_executed'])

    def test_original_default_timing_catalog(self):
        data=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=timing_compare.run_catalog(data)
        from src.video_research.reference import MODE_IDS
        self.assertEqual(report['case_count'],30)
        self.assertEqual([int(c['mode'],16) for c in report['cases']],list(MODE_IDS))
        cases={int(c['mode'],16):c for c in report['cases']}
        for case in timing_compare.run_original(data)['cases']:
            actual=cases[int(case['mode'],16)]
            for field,value in case.items():self.assertEqual(actual[field],value)
        wide=[c for c in report['cases'] if c['frame_width']==7008]
        self.assertEqual([c['mode'] for c in wide],['0xa000','0xa100','0x880','0x8c0'])
        self.assertTrue(all(c['quantity_ratio_to_0821']>1.98 for c in wide))
        self.assertEqual((cases[0x5002]['frame_width'],cases[0x5002]['frame_height']),(3504,2336))
        self.assertEqual(cases[0x5002]['quantity_ratio_to_0821'],1.0)
        self.assertAlmostEqual(cases[0x0ae0]['quantity_ratio_to_0821'],0.5)
        self.assertTrue(report['all_original_default_mode_rows_compared'])
        for flag in ('physical_unit_verified','actual_frame_cadence_verified',
            'full_sensor_field_of_view_verified','runtime_override_excluded',
            'sensor_to_encoder_path_verified','hardware_impossibility_proven',
            'camera_io','installable'):
            self.assertIs(report[flag],False)

    def test_original_default_timing_comparison(self):
        data=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        static=timing_compare.inspect(data)
        self.assertEqual(static['original_scale'],256.0)
        transfer=static['downstream_transfer']
        self.assertEqual(transfer['vtable_entries'],{'0x28':'0x98d35b','0x2c':'0x98d3db','0x30':'0x98d37d'})
        self.assertFalse(transfer['hardware_timing_consumer_verified'])
        override=static['conditional_override']
        self.assertEqual(override['records'],2)
        self.assertEqual([x['request_offset'] for x in override['replacement_fields']],['0x0','0x4','0x8','0x9','0xa'])
        self.assertFalse(override['live_values_or_writers_verified'])
        self.assertFalse(override['override_executed'])
        self.assertEqual(override['shadow_binding']['original_rows'][0],
            {'property_id':'0xbc0016','destination':'0x1211040','size':256})
        self.assertFalse(override['shadow_binding']['storage_loaded_or_event_dispatched'])
        report=timing_compare.run_original(data)
        self.assertEqual(report['quantity_ratio_0880_over_0821'],2.0)
        self.assertEqual(report['quantity_ratio_5002_over_0821'],1.0)
        spatial=static['lower_resolution_candidate']
        self.assertEqual((spatial['frame_width'],spatial['frame_height']),(3504,2336))
        self.assertEqual((spatial['comparison_width'],spatial['comparison_height']),(7008,4672))
        self.assertFalse(spatial['full_sensor_field_of_view_verified'])
        self.assertFalse(spatial['native_4k_detail_verified'])
        self.assertEqual([c['mode_multiplier'] for c in report['cases']],[2,1,1])
        self.assertTrue(report['original_table_inputs'])
        for flag in ('rounding_or_downstream_helpers_executed','physical_unit_verified',
            'actual_frame_cadence_verified','driver_readiness_fabricated','camera_io','installable'):
            self.assertIs(report[flag],False)

    @unittest.skipUnless(os.environ.get('A7C2_VIDEO_MPR_REFERENCE'),'Requires private original libmpr.so.')
    def test_original_mpr_bitrate(self):
        data=Path(os.environ['A7C2_VIDEO_MPR_REFERENCE']).read_bytes()
        self.assertEqual(mpr_bitrate.inspect(data)['units']['debug_divisor'],1000)
        report=mpr_bitrate.run_original(data)
        self.assertEqual([c['target_kbps'] for c in report['cases']],
            [200000,150000,140000,100000,60000,0,0,0,0])
        chain=mpr_bitrate.run_parameter_chain(Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes(),data)
        self.assertEqual([c['target_mbps'] for c in chain['cases']],[200,150,200,140,100,60])
        self.assertEqual(chain['cases'][0]['frame_rate_name'],'FRAME_RATE_59_94P')
        for flag in ('continuous_execution_verified','encoder_invoked','measured_bitrate_verified',
                     'uncropped_capability_verified','camera_io','installable'):
            self.assertIs(chain[flag],False)

    def test_original_mpr_encoding_parameters(self):
        data=Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes()
        static=mpr_encoding.inspect(data)
        self.assertEqual(static['library_import'][0]['name'],'_ZN3mpr16SetMovieRecParamERKNS_13movieRecParamE')
        report=mpr_encoding.run_original(data)
        self.assertEqual([c['quality_enum'] for c in report['cases']],[22,13,22,37,12,10])
        self.assertEqual([c['rate_enum'] for c in report['cases']],[7,7,5,3,3,3])
        self.assertEqual(report['cases'][0]['names'][0]['text'],'VPC_AVC_3840x2160_422_10BIT_LONG')
        self.assertEqual(report['cases'][0]['names'][1]['text'],'FRAME_RATE_59_94P')
        for flag in ('quality_bitrate_verified','encoder_called','camera_io','recording_verified','installable'):
            self.assertIs(report[flag],False)

    def test_original_mpr_quality_builder(self):
        data=Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes()
        static=mpr_quality.inspect(data)
        self.assertEqual(static['getters']['0x28662bc'],'0x7e6ce80')
        report=mpr_quality.run_original(data)
        self.assertEqual(report['case_count'],6)
        self.assertEqual([(c['output_90'],c['output_a0'],c['output_a4']) for c in report['cases']],
            [(20,18,1),(20,16,0),(18,18,1),(15,15,1),(15,13,0),(15,9,0)])
        self.assertIs(report['entire_builder_executed'],True)
        self.assertIs(report['original_getters_executed'],True)
        for flag in ('helpers_stubbed','encoder_request_sent','numeric_bitrate_verified','physical_recording_verified','camera_io','installable'):
            self.assertIs(report[flag],False)

    def test_original_availability_initialization(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        metadata=availability_init.inspect(cp)
        self.assertEqual(metadata['object'],'0x18aee1c')
        self.assertEqual(metadata['embedded_table_object'],hex(0x18aee1c+0x68c))
        report=availability_init.run_original(cp)
        self.assertEqual([c['returned_mode'] for c in report['cases']],[None,'0x821','0x880','0x821'])
        self.assertTrue(all(c['disabled_virtual_submission_result']==0 for c in report['cases']))
        self.assertTrue(all(c['submission_request_dereferenced'] is False for c in report['cases']))
        self.assertIs(report['original_graph_construction_executed'],True)
        self.assertEqual(report['original_table_fields_verified']['0x34'],'0xee01d6')
        self.assertEqual(report['original_table_fields_verified']['0x10'],'0x25dc04c')
        self.assertIs(report['original_handle_binding_executed'],True)
        self.assertIs(report['boot_execution_verified'],False)

    def test_original_movie_selector_candidates(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        metadata=movie_selector.inspect(cp)
        self.assertEqual([m['present_in_original_table'] for m in metadata['format_three_candidates']],[True,False,False,True])
        self.assertEqual(metadata['inventory_frames'][0]['width'],4608)
        report=movie_selector.run_original(cp)
        self.assertEqual([c['returned_mode'] for c in report['cases']],[None,'0x821',None,'0x821',None])
        self.assertEqual(report['cases'][0]['original_queries'],['0x820'])
        self.assertIs(report['availability_runtime_binding_verified'],False)

    def test_original_movie_rate_projection(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        report=movie_selector.run_rate_projection(cp)
        self.assertEqual([c['selector_branch'] for c in report['cases']],['0x4c082e','0x4c082e','0x4c084a','0x4c03ae'])
        with self.assertRaises(ValueError):movie_selector.run_rate_projection(b'bad')

    def test_original_snapshot_selector_fields(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        metadata=selector_fields.inspect(cp)
        self.assertEqual(metadata['mappings'][1]['selector_object_offset'],'0x3c0')
        self.assertEqual(metadata['mappings'][1]['source_snapshot_offset'],'0x28')
        report=selector_fields.run_original(cp)
        self.assertEqual([c['format_to_selector_3c0'] for c in report['cases']],[3]*4)
        self.assertIs(report['precondition_gates_executed'],False)

    def test_original_mode_sequence_provenance(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        metadata=mode_sequence.inspect(cp)
        self.assertEqual(metadata['static_records'],246)
        self.assertEqual([p['selector_writes'] for p in metadata['generated_example']['phases']],[[6],[25],[],[],[],[],[7]])
        self.assertIs(metadata['generated_example']['configuration_index_validity_verified'],False)
        self.assertEqual(metadata['dynamic_records']['count'],62)
        self.assertEqual(metadata['getter_to_snapshot']['source'],'0x1a52aa0')
        report=mode_sequence.run_original(cp)
        self.assertEqual([c['writes'] for c in report['cases']],[12,12,1,12])
        self.assertIs(report['mode_enum_names_verified'],False)

    def test_original_selector_state_provenance(self):
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        metadata=selector_state.inspect(cp)
        self.assertEqual(metadata['selector_word']['snapshot_offset'],'0x19b0')
        self.assertEqual(metadata['instance_pointer_0c']['value'],hex(0x172fe50+0xe18))
        report=selector_state.run_original(cp)
        self.assertEqual([c.get('selector_stop') for c in report['cases']],
            ['0x4c04a0','0x4c071a','0x4c0392','0x4c0392','0x4c0392',None])
        self.assertIs(report['cases'][-1]['rejected_before_diagnostics'],True)
        self.assertIs(report['runtime_mode_value_verified'],False)
        self.assertIs(report['selector_branch_body_executed'],False)

    def test_original_movie_numeric_path(self):
        ap=Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes()
        cp=Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()
        metadata=movie.inspect(ap,cp)
        self.assertEqual(metadata['cp_format_rate_table']['cell_3_0'],1)
        self.assertEqual(metadata['diagnostic_parameter_binding']['fields']['0x11'],'raw')
        report=movie.run_ap_original(ap)
        self.assertEqual([c['builder_rate'] for c in report['cases'][:3]],[20,18,15])
        self.assertEqual([c['wire_bytes_8_9_10'] for c in report['cases'] if c['phase']=='builder'],[[3,0,0],[3,1,0],[3,4,0]])
        self.assertIs(report['fragments_executed_separately'],True)
        report=movie.run_cp_original(cp)
        self.assertEqual([c['normalized_rate'] for c in report['cases'][:3]],[0,1,2])
        self.assertEqual([c['selected_accept_path'] for c in report['cases'][3:]],[True,True,False,False])
        self.assertIs(report['uncropped_capability_verified'],False)

    def test_original_apsc_policy_path(self):
        original=Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes()
        metadata=apsc.inspect(original)
        self.assertEqual(metadata['setting_state'],'0x7e6e620')
        menu=apsc.run_menu_values_original(original)
        self.assertEqual([c['setting_result'] for c in menu['cases']],['0x0','0x1','0x2','0xffffffff','0xffffffff'])
        self.assertIs(menu['runtime_record_selection_verified'],False)
        report=apsc.run_original(original)
        self.assertEqual(len(report['cases']),16)
        self.assertEqual([c['payload_byte8'] for c in report['cases']],
            [2,2,2,2,1,2,0,None,0,0,0,0,None,None,None,None])
        self.assertIs(report['numeric_enum_names_verified'],False)
        cp=handler.run_original(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes(),message_id=0x40a2)
        self.assertEqual(cp['static_dispatch_row']['handler'],'0x35858d')
        self.assertEqual(cp['case_count'],62)
        self.assertEqual({c['result_field'] for c in cp['cases']},{'0x29c','0x2a4'})
        self.assertIs(cp['message_delivery_verified'],False)

    def test_original_setting_static_flow(self):
        report=setting_flow.inspect(Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes())
        self.assertEqual(report['dispatcher']['target'],'0x2dd4e24')
        self.assertEqual(report['dispatcher']['index'],'0x9c')
        self.assertIs(report['dispatcher']['queue_producer_verified'],True)
        fragments=setting_flow.run_original(Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes())
        self.assertEqual(len(fragments['cases']),8)
        self.assertEqual(fragments['cases'][1]['stopped_before'],'0x353367c')
        self.assertEqual([c['command_value'] for c in fragments['cases'][4:]],[0,1,None,None])
        self.assertIs(fragments['user_setting_provenance_verified'],False)
        self.assertEqual(report['state_address'],'0x7e59d18')
        self.assertIs(report['continuous_execution_verified'],False)
        self.assertIs(report['dispatcher']['ui_identifier_verified'],False)
        self.assertEqual(len(report['reviewed_ranges']),10)

    def test_original_registration_and_predicate_fragments(self):
        original=Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes()
        metadata=registration.inspect(original)
        self.assertEqual(metadata['table_base'],'0x58f03a8')
        self.assertIs(metadata['restriction_enforcement_verified'],False)
        self.assertIn('caution',metadata['subsystem'])
        self.assertEqual(metadata['records'][1]['condition_pair'][1]['name'],
                         'VAL_imager_frame_size_IMAGER_FRAME_SIZE_APSC')
        report=registration.run_original(original)
        self.assertEqual([c['selected_callback'] for c in report['registration_cases']],
                         ['0x1871eb8','0x1871ef8','0x1870400','0x18727c4'])
        self.assertEqual([c['predicate_result'] for c in report['predicate_cases']],[0,1,0])
        self.assertIs(report['full_value_zero_verified'],False)
        self.assertIs(report['fragments_executed_separately'],True)
        rates=registration.run_rate_original(original)
        self.assertEqual([c['predicate_result'] for c in rates['cases']],[0,1,0,1,0,0])
        self.assertIs(rates['ff_restriction_evaluated'],False)
        keys={p['property']['index'] for p in metadata['records'][3]['condition_pairs']}
        self.assertTrue({'0x102','0x7db','0x7e4'}<=keys)

    def test_original_conditional_state_loop(self):
        report=dispatch.run_state_lifecycle_original(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes())
        self.assertEqual([c['changed_state_words'] for c in report['cases']],[0,350,0])
        self.assertIs(report['runtime_flag_value_verified'],False)
        self.assertIs(report['earlier_calls_executed'],False)

    def test_original_check_callback(self):
        report=check.run_original(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes())
        self.assertEqual(report['case_count'],11)
        self.assertEqual({c['observed_boundary'] for c in report['cases']},{'returned','diagnostic'})
        self.assertIs(report['diagnostics_executed'],False)
        self.assertIs(report['context_writes'],False)
        self.assertIs(report['message_delivery_verified'],False)

    def test_original_snapshot_copy(self):
        report=snapshot.run_original(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes())
        self.assertEqual(report['length'],0xd64)
        self.assertEqual(report['source'],'0x165a720')
        self.assertEqual(report['destination'],'0x172fe50')
        self.assertIs(report['initialization_snapshot_only'],True)
        self.assertIs(report['live_synchronization_verified'],False)
        self.assertEqual(report['unknown_helpers_executed'],0)

    def test_separate_fragments(self):
        reports = (ap.run_original(Path(os.environ['A7C2_VIDEO_AP_REFERENCE']).read_bytes()),
            dispatch.run_original(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()),
            handler.run_original(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']).read_bytes()))
        self.assertEqual([r['case_count'] for r in reports], [16, 4, 62])
        for report in reports:
            for flag in ('camera_io','firmware_file_written','movie_path_verified','recording_verified','installable'):
                self.assertIs(report[flag], False)
        self.assertIs(reports[0]['message_submitted'], False)
        self.assertIs(reports[1]['transport_verified'], False)
        self.assertIs(reports[2]['fragments_executed_separately'], True)
        self.assertEqual(reports[2]['unknown_helpers_executed'], 0)

if __name__ == '__main__': unittest.main()
