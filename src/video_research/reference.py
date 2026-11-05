"""Version-pinned public research facts, not a flash manifest.

The CP layout and descriptor reconstruction derive from chocotan/a7c2-re.
See NOTICE.txt for its MIT license. No Sony firmware bytes are distributed.
These identity checks are local to this NEW offline parser; existing FL23
installers and their edited-byte compatibility rules are not changed.
"""
from dataclasses import dataclass

MODEL = 'ILCE-7CM2'
FIRMWARE = '2.01'
SOURCE_COMMIT = 'd79257cf6815642b9794fa5b590c9626bfbc2c67'
SOURCE_ROOT = f'https://github.com/chocotan/a7c2-re/blob/{SOURCE_COMMIT}/'
SOURCE_DIRECTORY = 'report/2026-10-19-cmos-input-path/'
SOURCES = (
    SOURCE_ROOT + SOURCE_DIRECTORY + 'tools/verify_opengate_6k.py',
    SOURCE_ROOT + SOURCE_DIRECTORY + 'OPENGATE-6K-DIRECT.md',
)


@dataclass(frozen=True)
class ImageSpec:
    name: str
    size: int
    sha256: str


CP = ImageSpec('cpapp-b.bin', 18090880,
               'f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428')
AP = ImageSpec('appFw.so', 99960744,
               '2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b')
CP_BASE = 0x108000
MODE_IDS_VA = 0xDE99D4
FRAME_TABLE_VA = 0xEE01D6
FRAME_STRIDE = 0x26
COLUMN_TABLE_VA = 0x10FE8E0
DESCRIPTOR_TABLE_VA = 0x10FD8D0
DESCRIPTOR_COUNT = 247
PATCH_TABLE_VA = 0x10FDCB0
PATCH_COUNT = 129
PATCH_STRIDE = 24
COLUMN_COUNT = 18
MODE_IDS = (
    0x5000, 0x5200, 0xC100, 0x5400, 0xC000, 0x5002, 0x5020,
    0xA000, 0xA100, 0x0880, 0x08C0, 0x0AE0, 0x0B20, 0x0BC0,
    0x5001, 0x5201, 0x5401, 0xC010, 0xC110, 0x5004, 0x5021,
    0xA030, 0xA130, 0x0821, 0x08C1, 0x0AE1, 0x0B21, 0x0BC1,
    0x8000, 0xE000,
)
# Only the cross-checks independently asserted by the pinned research script.
FRAME_CHECKS = {0x5002: (3504, 2336), 0xA000: (7008, 4672), 0x0880: (7008, 3942)}
COMMAND_CHECKS = {0x5002: 0x08, 0xA000: 0x01, 0x0880: 0x10,
                  0xA030: 0x05, 0x0821: 0x15}
DIFF_CHECKS = (
    (0xA000, 0xA030, frozenset((1, 5, 0xE, 0x10, 0x19))),
    (0xA100, 0x0880, frozenset((1, 5, 0xE, 0x10, 0x19))),
    (0x5002, 0x5004, frozenset((5, 6, 7, 8, 9, 0xE, 0x10, 0x19))),
)
CALLFLOW = (
    ('SetModeAsync', 0x989FDA),
    ('outer+0x24', 0x98CFDE),
    ('outer+0x10c', 0x39AFFC),
    ('mode-column selection', 0x98C806),
    ('descriptor consumption', 0x98BF52),
    ('P2S packet encoding', 0x98CB0C),
    ('P2S payload submission', 0x98BB72),
)


def boundaries() -> dict:
    """Every report carries explicit negative execution/acceptance facts."""
    return dict(camera_io=False, network_io=False, firmware_executed=False,
                firmware_written=False, runtime_overrides_included=False,
                recording_verified=False, hardware_verified=False,
                installable=False)


def catalog() -> dict:
    return dict(
        schema='a7c2-video-catalog/1', model=MODEL, firmware=FIRMWARE,
        scope='Published static references; not locally parsed firmware or a patch.',
        sources=list(SOURCES), boundaries=boundaries(),
        images=[dict(name=s.name, size=s.size, sha256=s.sha256) for s in (AP, CP)],
        profiles=[
            dict(id='ff4k60', status='research_candidate', mode='0x5002',
                 published_frame=[3504, 2336], target_rate='60000/1001',
                 note='Full-width readout, timing, ISP and recording require validation.'),
            dict(id='4k120', status='unverified', mode=None, target_rate='120000/1001',
                 note='No validated A7C II sensor-to-encoder profile is supplied.'),
            dict(id='af120', status='unverified', mode=None, target_rate=None,
                 note='AF requests and lock notifications do not measure AF computation cadence.'),
        ],
        published_callflow=[dict(name=name, cp_va=hex(va), file_offset=hex(va-CP_BASE))
                            for name, va in CALLFLOW],
        callflow_verified_by_this_tool=False,
        caution='CP virtual addresses, file offsets and sensor command IDs are different domains.',
    )
