"""Synthetic offline regressions. No Sony firmware, camera or network needed.

Run: python -m unittest discover -s dev/video_research -v
Optional private integration: A7C2_VIDEO_CP_REFERENCE=/local/cpapp-b.bin
"""
import ast
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.video_research import reference as ref
from src.video_research.cli import main, emit
from src.video_research.inventory import (
    LayoutError, _Reader, _parse_cp, _crosscheck, command_diff, fingerprint,
    inspect_images, read_image,
)
from src.video_research.planner import plan


class Synthetic:
    """Fabricated tables, NOT a private or redistributed Sony image."""
    def __init__(self):
        self.data = bytearray(ref.CP.size)
        self.descriptors = 0x1200000
        self.columns = {0x5002: 0, 0xA000: 1, 0xA100: 2, 0x0880: 3,
                        0x5004: 4, 0xA030: 5, 0x0821: 6}
        for i, mode in enumerate(ref.MODE_IDS):
            self.put('<I', ref.MODE_IDS_VA+i*4, mode)
            self.put('<I', ref.COLUMN_TABLE_VA+i*4, self.columns.get(mode, 7))
            width, height = ref.FRAME_CHECKS.get(mode, (32, 18))
            row = ref.FRAME_TABLE_VA+i*ref.FRAME_STRIDE
            self.put('<H', row+8, width)
            self.put('<H', row+0x1A, height)
        for i in range(ref.DESCRIPTOR_COUNT):
            descriptor = self.descriptors+i*4
            self.put('<I', ref.DESCRIPTOR_TABLE_VA+i*4, descriptor)
            self.put('<H', descriptor, i+1)
            self.put('<B', descriptor+2, 0)
        for i in range(ref.PATCH_COUNT):
            row = ref.PATCH_TABLE_VA+i*ref.PATCH_STRIDE
            self.put('<I', row, self.descriptors+i*4+2)
        for col, value in enumerate((8, 1, 2, 16, 8, 5, 21)):
            self.value(1, col, value)
        for cid in (5, 14, 16, 25):
            for col, value in ((0, 1), (4, 2), (1, 1), (5, 2), (2, 1), (3, 2)):
                self.value(cid, col, value)
        for cid in (6, 7, 8, 9):
            self.value(cid, 0, 1)
            self.value(cid, 4, 2)

    def put(self, fmt, va, value):
        struct.pack_into(fmt, self.data, va-ref.CP_BASE, value)

    def value(self, command, col, value):
        self.put('<B', ref.PATCH_TABLE_VA+(command-1)*ref.PATCH_STRIDE+4+col, value)


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Synthetic()
        cls.modes = _parse_cp(cls.fixture.data)
        cls.index = {m.mode_id: m for m in cls.modes}

    def test_all_30_modes_in_order(self):
        self.assertEqual(tuple(m.mode_id for m in self.modes), ref.MODE_IDS)

    def test_published_crosschecks_on_synthetic_data(self):
        _crosscheck(self.modes)

    def test_5002_frame_and_command(self):
        m = self.index[0x5002]
        self.assertEqual((m.width, m.height, m.commands[1]), (3504, 2336, 8))

    def test_each_mode_gets_its_own_map(self):
        self.assertIsNot(self.modes[0].commands, self.modes[1].commands)

    def test_patch_pointer_targets_data_byte_not_descriptor_start(self):
        self.assertEqual(self.index[0xA030].commands[1], 5)

    def test_all_published_diff_sets(self):
        for a, b, expected in ref.DIFF_CHECKS:
            with self.subTest(before=a, after=b):
                self.assertEqual(set(command_diff(self.index[a], self.index[b])), expected)

    def test_summary_omits_full_command_payload(self):
        self.assertNotIn('commands', self.index[0x5002].summary())
        self.assertEqual(self.index[0x5002].summary()['command_0001'], 8)

    def test_lower_and_upper_bounds(self):
        reader = _Reader(b'\0'*8)
        for va in (0, ref.CP_BASE-1, ref.CP_BASE+5, 2**64):
            with self.subTest(va=va), self.assertRaises(LayoutError):
                reader.u32(va)
        self.assertEqual(reader.u32(ref.CP_BASE+4), 0)

    def test_truncated_image(self):
        with self.assertRaises(LayoutError):
            _parse_cp(b'\0'*64)

    def changed(self, va, value, fmt='<I'):
        data = bytearray(self.fixture.data)
        struct.pack_into(fmt, data, va-ref.CP_BASE, value)
        return data

    def test_wrong_mode_order(self):
        with self.assertRaisesRegex(LayoutError, 'IDs/order'):
            _parse_cp(self.changed(ref.MODE_IDS_VA, 0))

    def test_invalid_column(self):
        for value in (18, 0xFFFFFFFF):
            with self.subTest(column=value), self.assertRaisesRegex(LayoutError, 'column'):
                _parse_cp(self.changed(ref.COLUMN_TABLE_VA, value))

    def test_descriptor_below_mapping(self):
        with self.assertRaises(LayoutError):
            _parse_cp(self.changed(ref.DESCRIPTOR_TABLE_VA, 1))

    def test_descriptor_past_end(self):
        with self.assertRaises(LayoutError):
            _parse_cp(self.changed(ref.DESCRIPTOR_TABLE_VA, ref.CP_BASE+ref.CP.size))

    def test_patch_pointer_underflow(self):
        with self.assertRaises(LayoutError):
            _parse_cp(self.changed(ref.PATCH_TABLE_VA, 1))

    def test_command_check_failure(self):
        va = ref.PATCH_TABLE_VA+4
        modes = _parse_cp(self.changed(va, 0, '<B'))
        with self.assertRaisesRegex(LayoutError, 'command-0001'):
            _crosscheck(modes)

    def test_frame_check_failure(self):
        va = ref.FRAME_TABLE_VA+5*ref.FRAME_STRIDE+8
        modes = _parse_cp(self.changed(va, 3200, '<H'))
        with self.assertRaisesRegex(LayoutError, 'frame'):
            _crosscheck(modes)

    def test_diff_check_failure(self):
        va = ref.PATCH_TABLE_VA+(25-1)*ref.PATCH_STRIDE+4+5
        modes = _parse_cp(self.changed(va, 1, '<B'))
        with self.assertRaisesRegex(LayoutError, 'difference'):
            _crosscheck(modes)


class LocalIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_reads_without_changing_input(self):
        path = self.root/'input.bin'
        path.write_bytes(b'not firmware')
        before = path.stat().st_mtime_ns
        self.assertEqual(read_image(path), b'not firmware')
        self.assertEqual(path.stat().st_mtime_ns, before)

    def test_reject_empty(self):
        path = self.root/'empty.bin'
        path.touch()
        with self.assertRaises(ValueError):
            read_image(path)

    def test_reject_directory(self):
        with self.assertRaises(ValueError):
            read_image(self.root)

    def test_reject_oversized_before_reading(self):
        path = self.root/'large.bin'
        with path.open('wb') as stream:
            stream.truncate(128*1024*1024+1)
        with self.assertRaises(ValueError):
            read_image(path)

    def symlink(self, target, link):
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('Host does not permit creating test symlinks.')

    def test_reject_input_symlink(self):
        target, link = self.root/'input.bin', self.root/'link.bin'
        target.write_bytes(b'input')
        self.symlink(target, link)
        with self.assertRaises(ValueError):
            read_image(link)

    def test_unknown_input_is_not_parsed(self):
        path = self.root/'input.bin'
        path.write_bytes(b'not firmware')
        with patch('src.video_research.inventory._parse_cp', side_effect=AssertionError('must not parse')):
            report = inspect_images(path)
        self.assertEqual(report['status'], 'input_rejected')
        self.assertFalse(report['cp_layout_verified'])
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_fingerprint_requires_both_size_and_hash(self):
        data = b'example'
        spec = ref.ImageSpec('test', len(data)+1, hashlib.sha256(data).hexdigest())
        self.assertEqual(fingerprint(data, spec)['status'], 'unsupported_reference')

    def test_end_to_end_synthetic_reference_with_test_only_pin(self):
        data = Synthetic().data
        path = self.root/'synthetic.bin'
        path.write_bytes(data)
        spec = ref.ImageSpec('synthetic-not-sony', len(data), hashlib.sha256(data).hexdigest())
        with patch.object(ref, 'CP', spec):
            report = inspect_images(path)
        self.assertTrue(report['cp_layout_verified'])
        self.assertEqual(len(report['modes']), 30)
        self.assertFalse(report['boundaries']['hardware_verified'])

    def test_atomic_identity_rejection_survives_python_optimization(self):
        script = ROOT/'video_research.py'
        path = self.root/'input.bin'
        path.write_bytes(b'invalid')
        result = subprocess.run([sys.executable, '-O', '-B', str(script), 'inventory', '--cp', str(path)],
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'input_rejected')

    def test_explicit_private_report(self):
        path = self.root/'report.private.json'
        emit({'ok': True}, path)
        self.assertEqual(json.loads(path.read_text()), {'ok': True})
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_report_cannot_overwrite(self):
        path = self.root/'report.private.json'
        path.write_text('keep')
        with self.assertRaises(FileExistsError):
            emit({}, path)
        self.assertEqual(path.read_text(), 'keep')

    def test_report_cannot_target_firmware(self):
        with self.assertRaises(ValueError):
            emit({}, self.root/'appFw.so')

    def test_report_cannot_alias_input(self):
        path = self.root/'report.private.json'
        path.write_text('input')
        with self.assertRaisesRegex(ValueError, 'alias'):
            emit({}, path, (path,))
        self.assertEqual(path.read_text(), 'input')

    def test_output_symlink_does_not_create_target(self):
        target, link = self.root/'missing', self.root/'report.private.json'
        self.symlink(target, link)
        with self.assertRaises(OSError):
            emit({}, link)
        self.assertFalse(target.exists())

    def test_missing_input_error_does_not_leak_private_path(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(['inventory', '--cp', str(self.root/'personal-name.bin')])
        self.assertEqual(code, 2)
        self.assertNotIn(str(self.root), stderr.getvalue())
        self.assertNotIn('personal-name', stderr.getvalue())


class PlanAndBoundaryTests(unittest.TestCase):
    def test_no_input_plan_remains_blocked(self):
        report = plan('ff4k60', inspect_images())
        self.assertEqual(report['status'], 'blocked_research_only')
        self.assertIn('cp_reference', report['blocking_checks'])
        self.assertIsNone(report['geometry']['locally_observed'])

    def test_fractional_rate_not_rounded_to_60(self):
        report = plan('ff4k60', inspect_images())
        self.assertEqual(report['target_rate']['numerator'], 60000)
        self.assertEqual(report['target_rate']['denominator'], 1001)
        self.assertAlmostEqual(report['target_frame_period_ms']['decimal'], 16.683333333333334)

    def test_odd_height_is_not_silently_selected_as_roi(self):
        geometry = plan('ff4k60', inspect_images())['geometry']
        self.assertEqual(geometry['ideal_16_9_height']['numerator'], 1971)
        self.assertFalse(geometry['ideal_420_height_even'])
        self.assertFalse(geometry['source_width_multiple_of_32'])
        self.assertIsNone(geometry['selected_crop'])
        self.assertIsNone(geometry['selected_stride'])

    def test_even_forged_inventory_cannot_enable_installer(self):
        fake = dict(status='forged', cp_layout_verified=True,
                    images={'cp': {'status': 'matched'}, 'ap': {'status': 'matched'}},
                    modes=[dict(mode_id='0x5002', width=3504, height=2336)])
        for profile in ('ff4k60', '4k120', 'af120'):
            with self.subTest(profile=profile):
                report = plan(profile, fake)
                self.assertFalse(report['boundaries']['installable'])
                self.assertFalse(report['boundaries']['recording_verified'])
                self.assertEqual(report['write_operations'], [])
                self.assertTrue(report['blocking_checks'])

    def test_4k120_does_not_reuse_unverified_5002_timing(self):
        report = plan('4k120', inspect_images())
        self.assertIsNone(report['geometry'])
        self.assertIn('high_speed_sensor_mode', report['blocking_checks'])
        self.assertEqual(report['target_rate']['numerator'], 120000)

    def test_af120_is_not_a_video_framerate(self):
        report = plan('af120', inspect_images())
        self.assertIsNone(report['target_rate'])
        self.assertIn('af_cadence', report['blocking_checks'])

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            plan('unlimited', {})

    def test_catalog_is_not_local_verification(self):
        report = ref.catalog()
        self.assertFalse(report['callflow_verified_by_this_tool'])
        self.assertFalse(report['boundaries']['hardware_verified'])

    def test_help_and_catalog_do_not_import_camera_libraries(self):
        code = (
            'import sys; from src.video_research.cli import main; '
            "main(['catalog']); "
            "assert not any(n.startswith(('usb', 'camera_runtime', 'desktopapp', 'pmca', 'PySide6')) "
            'for n in sys.modules)'
        )
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_has_no_write_or_unsafe_override_command(self):
        for args in (['install'], ['flash'], ['inventory', '--cp', 'x', '--allow-unknown']):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                main(args)
            self.assertEqual(exc.exception.code, 2)

    def test_production_import_allowlist(self):
        allowed = {'argparse', 'dataclasses', 'fractions', 'hashlib', 'json', 'os',
                   'pathlib', 'stat', 'struct', 'sys'}
        for path in (ROOT/'src/video_research').glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        self.assertIn(item.name.split('.')[0], allowed, str(path))
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    self.assertIn(node.module.split('.')[0], allowed, str(path))

    def test_pinned_callflow_address_domains(self):
        for item in ref.catalog()['published_callflow']:
            self.assertEqual(int(item['cp_va'], 16)-int(item['file_offset'], 16), ref.CP_BASE)


class PrivateReferenceTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('A7C2_VIDEO_CP_REFERENCE'), 'No private original CP fixture supplied.')
    def test_exact_original_cp(self):
        report = inspect_images(Path(os.environ['A7C2_VIDEO_CP_REFERENCE']))
        self.assertTrue(report['cp_layout_verified'], report['errors'])
        self.assertEqual(len(report['modes']), 30)
        self.assertFalse(report['boundaries']['recording_verified'])


if __name__ == '__main__':
    unittest.main()
