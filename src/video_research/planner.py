"""Evidence-gap planning, deliberately NOT a firmware patch generator."""
from fractions import Fraction

from . import reference as ref

PROFILES = ('ff4k60', '4k120', 'af120')


def fraction(value: Fraction) -> dict:
    return dict(numerator=value.numerator, denominator=value.denominator, decimal=float(value))


def plan(profile: str, inventory: dict) -> dict:
    """Consume an in-process inventory, never user-supplied acceptance flags.

    The CLI always creates the inventory from local files. Even a caller-supplied
    dict cannot make this assessment installable or create a write operation.
    """
    if profile not in PROFILES:
        raise ValueError('Unknown research profile.')
    images = inventory.get('images', {})
    observed = next((m for m in inventory.get('modes', []) if m['mode_id'] == '0x5002'), None)
    checks = []

    def check(name, state, reason):
        checks.append(dict(id=name, status=state, reason=reason))

    for key in ('cp', 'ap'):
        state = images.get(key, {}).get('status', 'missing')
        check(key + '_reference', 'passed' if state == 'matched' else state,
              'Exact original reference identity; NOT hardware or installation acceptance.')
    check('cp_layout', 'passed' if inventory.get('cp_layout_verified') else 'unverified',
          'Stored mode, frame and descriptor tables plus published cross-checks.')
    geometry = None
    rate = None
    if profile == 'ff4k60':
        rate = Fraction(60000, 1001)
        check('mode_5002', 'passed' if observed and inventory.get('cp_layout_verified') else 'unverified',
              'Published candidate is 3504x2336; mode timing is not inferred from its dimensions.')
        width, height = 3504, 2336
        ideal_height = Fraction(width * 9, 16)
        geometry = dict(
            basis='Published dimensions, arithmetic only; NOT a selected ISP configuration.',
            published_source=[width, height], locally_observed=observed,
            target=[3840, 2160], ideal_16_9_height=fraction(ideal_height),
            ideal_420_height_even=ideal_height.denominator == 1 and ideal_height.numerator % 2 == 0,
            source_width_multiple_of_32=width % 32 == 0,
            horizontal_upscale=fraction(Fraction(3840, width)),
            selected_crop=None, selected_stride=None, selected_sensor_timing=None,
            warning='3504x1971 is an ideal odd-height rectangle, NOT an approved YUV420/ISP ROI. '
                    'Padding/alignment, visible versus coded size, and field of view remain unresolved.')
    elif profile == '4k120':
        rate = Fraction(120000, 1001)
        check('high_speed_sensor_mode', 'unverified',
              'No validated 4K120 sensor mode/profile is included; 120p enums alone are insufficient.')
    else:
        check('af_cadence', 'unverified',
              'First distinguish sensor statistics, independent AF computations, lens commands and callbacks.')
    blockers = (
        ('sensor_timing', 'Measure actual input frames; stored command bytes are not wire or timing proof.'),
        ('isp_geometry', 'Establish input format, CFA phase, ROI, scaling, stride and alignment.'),
        ('buffer_lifetime', 'Verify allocation backing, ownership, synchronization and buffer retirement.'),
        ('encoder_route', 'Verify the chosen codec/profile and every parameter consumer, not just the menu.'),
        ('recording', 'Independent decode, distinct frames, timestamps, FoV and audio sync required.'),
        ('af_ae_stabilization', 'Check AF/AE and stabilization under the actual changed readout mode.'),
        ('thermal_regression', 'Measure sustained operation; keep temperature and power protections.'),
        ('recovery', 'Device-specific load/recovery checks must precede any proposed persistent install.'),
    )
    for name, reason in blockers:
        check(name, 'unverified', reason)
    return dict(
        schema='a7c2-video-research-plan/1', profile=profile, model=ref.MODEL, firmware=ref.FIRMWARE,
        status='blocked_research_only', is_patch_manifest=False, boundaries=ref.boundaries(),
        sources=list(ref.SOURCES), inventory_status=inventory.get('status'),
        target_rate=fraction(rate) if rate else None,
        target_frame_period_ms=fraction(Fraction(1000, 1)/rate) if rate else None,
        geometry=geometry, checks=checks,
        blocking_checks=[c['id'] for c in checks if c['status'] != 'passed'],
        write_operations=[], note='No firmware output or USB write endpoint exists in this module.')
