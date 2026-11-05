"""Explicit Sony-download integration runner; never installs firmware or opens a camera.

Separate from the standard-library-only offline CLI. Requires the project's
vendored fwtool and pycryptodomex only when extracting the official package.
Firmware lives in a private temporary directory and is never published.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SIZE = 1_139_929_560
MODEL_CODE = 0x20030014
PAGES = (
    'https://www.sony.com/electronics/support/software/00301105',
    'https://support.d-imaging.sony.co.jp/www/cscs/firm/?mdl=ILCE-7CM2',
)
HOSTS = frozenset(('www.sony.com', 'support.d-imaging.sony.co.jp',
                   'di.update.sony.net'))
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36'
CHUNK = 4 * 1024 * 1024


def trusted_url(url: str, *, package: bool = False) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError('Only HTTPS URLs on the exact Sony download host allowlist are accepted.')
    if package and not parsed.path.endswith('/BODYDATA.DAT'):
        raise ValueError('Expected the official BODYDATA.DAT download path.')
    return url


class SonyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trusted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_sony(url: str):
    trusted_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    return urllib.request.build_opener(SonyRedirect()).open(request, timeout=60)


def candidates(document: str, base: str) -> tuple[str, ...]:
    """Parse public HTML/JSON strings; never evaluate page scripts."""
    text = html.unescape(document).replace('\\/', '/').replace('\\u002F', '/')
    pattern = r'''(?:https://|//|/download/)[^\s<>"'\\]*?BODYDATA\.DAT(?:\?[^\s<>"'\\]*)?'''
    urls = set()
    for raw in re.findall(pattern, text):
        url = urllib.parse.urljoin(base, raw)
        try:
            urls.add(trusted_url(url, package=True))
        except ValueError:
            continue
    return tuple(sorted(urls))


def discover() -> tuple[str, str]:
    for page in PAGES:
        try:
            with open_sony(page) as response:
                data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise ValueError('Official support page exceeds the bounded parser size.')
            text = data.decode('utf-8')
            if 'ILCE-7CM2' not in text or '2.01' not in text:
                raise ValueError('Support page no longer identifies the requested model/version.')
            urls = candidates(text, page)
            print(json.dumps({'event': 'official_page_checked', 'page': page,
                              'download_candidates': list(urls)}), flush=True)
            if len(urls) == 1:
                return urls[0], page
            if len(urls) > 1:
                raise ValueError('Ambiguous official downloads; review the support page.')
            # Public page resource names only; not the HTML, cookies or tokens.
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', text)
            print(json.dumps({'event': 'official_page_scripts',
                              'scripts': scripts[-12:]}), flush=True)
        except (OSError, ValueError, UnicodeError) as exc:
            print(json.dumps({'event': 'official_page_unavailable', 'page': page,
                              'error_type': type(exc).__name__}), flush=True)
    raise ValueError('No unique official 2.01 download found; no mirror or guessed URL used.')


def copy_exact(stream, output, expected: int) -> str:
    """Bound the transfer, reject both truncation and excessive data."""
    digest = hashlib.sha256()
    count = 0
    while block := stream.read(min(CHUNK, expected - count + 1)):
        count += len(block)
        if count > expected:
            raise ValueError('Download or component exceeds the expected byte count.')
        output.write(block)
        digest.update(block)
    if count != expected:
        raise ValueError('Download or component is truncated.')
    return digest.hexdigest()


def check_header(header) -> None:
    version = '%x.%02x' % (header.versionMajor, header.versionMinor)
    if header.model != MODEL_CODE or version != '2.01':
        raise ValueError('Official package model/version does not match ILCE-7CM2 2.01.')


def extract_components(source: Path, directory: Path, *, with_transport: bool = False, with_mpr: bool = False) -> dict:
    """Select AP/CP and optionally pinned OSAL/MPR dependencies only. No extractall, symlinks, calibration or native code."""
    sys.path.insert(0, str(ROOT / 'src/desktopapp/vendor'))
    sys.path.insert(0, str(ROOT))
    from fwtool.sony import dat, fdat
    from fwtool.archive import ext2, fat
    from src.video_research import reference as ref

    wanted = {item.name: item for item in (ref.AP, ref.CP)}
    if with_transport:
        from types import SimpleNamespace
        from osal_transport import SIZE, SHA
        wanted['libosal_uipc.so'] = SimpleNamespace(name='libosal_uipc.so',size=SIZE,sha256=SHA)
    if with_mpr:
        from types import SimpleNamespace
        from mpr_bitrate import SIZE, SHA
        wanted['libmpr.so'] = SimpleNamespace(name='libmpr.so',size=SIZE,sha256=SHA)
        from avbbc_receiver import SIZE, SHA
        wanted['libInfraAvbbc.so'] = SimpleNamespace(name='libInfraAvbbc.so',size=SIZE,sha256=SHA)
        from avbbc_receiver import DATAFLOW_SIZE, DATAFLOW_SHA
        wanted['dataflowInfraFramework.so'] = SimpleNamespace(name='dataflowInfraFramework.so',size=DATAFLOW_SIZE,sha256=DATAFLOW_SHA)
        from avbbc_receiver import KERNEL_SIZE, KERNEL_SHA
        wanted['osal_uipc.ko'] = SimpleNamespace(name='osal_uipc.ko',size=KERNEL_SIZE,sha256=KERNEL_SHA)
    found = {}

    def keep(name, stream, size):
        spec = wanted[name]
        if size != spec.size:
            raise ValueError('Original component size differs: ' + name)
        path = directory / name
        with path.open('xb') as output:
            digest = copy_exact(stream, output, spec.size)
        if digest != spec.sha256:
            raise ValueError('Original component SHA-256 differs: ' + name)
        found[name] = path
        print(json.dumps({'event': 'component_verified', 'name': name,
                          'size': spec.size, 'sha256': digest}), flush=True)

    with source.open('rb') as stream, tempfile.TemporaryFile() as decoded:
        outer = dat.readDat(stream)  # Includes the container CRC check.
        if outer.isLens or (0x054c, 0x0e8a) not in outer.normalUsbDescriptors:
            raise ValueError('Official container does not identify the A7C II body.')
        cipher, plain = fdat.decryptFdat(outer.firmwareData)
        check_header(fdat.FdatHeader.unpack(plain))
        plain.seek(0)
        # Decrypt bounded blocks into a seekable temporary stream.
        limit, written = 2 * 1024**3, 0
        while block := plain.read(CHUNK):
            written += len(block)
            if written > limit:
                raise ValueError('Decoded container exceeds its size bound.')
            decoded.write(block)
        decoded.seek(0)
        contents = fdat.readFdat(decoded)
        if contents.model != MODEL_CODE or contents.version != '2.01':
            raise ValueError('Decoded firmware identity differs.')
        with tarfile.open(fileobj=contents.firmware, mode='r:') as archive:
            for member in archive:
                if not member.isfile():
                    continue
                base = member.name.rsplit('/', 1)[-1]
                if base in wanted and base not in found:
                    keep(base, archive.extractfile(member), member.size)
                elif member.name.startswith('0700_part_image/') and member.size:
                    image = archive.extractfile(member)
                    reader = ext2.readExt2 if ext2.isExt2(image) else fat.readFat if fat.isFat(image) else None
                    if reader:
                        for entry in reader(image):
                            name = entry.path.rsplit('/', 1)[-1]
                            if name in wanted and name not in found and stat.S_ISREG(entry.mode):
                                entry.contents.seek(0, 2)
                                size = entry.contents.tell()
                                entry.contents.seek(0)
                                keep(name, entry.contents, size)
                if len(found) == len(wanted):
                    break
    if set(found) != set(wanted):
        raise ValueError('Official package does not contain every required component.')
    return {'files': found, 'decoder': cipher, 'container_crc_verified': True,
            'sony_rsa_signature_verified': False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-sony-download-terms', action='store_true',
                        help='Explicitly request a Sony-hosted download after reviewing its terms.')
    args = parser.parse_args(argv)
    if not args.accept_sony_download_terms:
        parser.error('Read the Sony support page and explicitly accept the download terms.')
    url, page = discover()
    with tempfile.TemporaryDirectory(prefix='a7c2-official-') as tmp:
        work = Path(tmp)
        work.chmod(0o700)
        source = work / 'BODYDATA.DAT'
        print('Downloading official ILCE-7CM2 2.01 to temporary storage.', flush=True)
        with open_sony(url) as response, source.open('xb') as output:
            trusted_url(response.geturl(), package=True)
            length = response.headers.get('Content-Length')
            if length is not None and int(length) != PACKAGE_SIZE:
                raise ValueError('Official download length changed; review before proceeding.')
            package_sha = copy_exact(response, output, PACKAGE_SIZE)
        print(json.dumps({'event': 'official_download_complete', 'page': page,
                          'url': url, 'size': PACKAGE_SIZE, 'sha256': package_sha}), flush=True)
        original = extract_components(source, work, with_transport=True, with_mpr=True)
        from src.video_research.inventory import inspect_images
        import os
        cp, ap = original['files']['cpapp-b.bin'], original['files']['appFw.so']
        report = inspect_images(cp, ap)
        if report['errors'] or not report['cp_layout_verified']:
            raise ValueError('Original-component inventory did not pass.')
        print(json.dumps({'event': 'original_inventory_verified',
                          'images': report['images'], 'mode_count': len(report['modes']),
                          'selected_mode': next(m for m in report['modes'] if m['mode_id'] == '0x5002'),
                          'differences': report['differences'],
                          'boundaries': report['boundaries'],
                          'download_network_io': True,
                          'container_crc_verified': original['container_crc_verified'],
                          'sony_rsa_signature_verified': original['sony_rsa_signature_verified']},
                         indent=2), flush=True)
        # Bounded original instruction fragments, not firmware boot/device execution.
        import osal_transport
        import avbbc_receiver
        import mpr_codec_transport
        import cp_movie_geometry
        import cp_stream_geometry
        import cp_lowres_route
        import cp_request_handoff
        import cp_timing_compare
        import cp_availability_init
        import cp_movie_selector
        import cp_selector_fields
        import cp_mode_sequence
        import cp_selector_state
        import mpr_bitrate
        import ap_mpr_encoding
        import ap_mpr_quality
        import movie_setting_flow
        import ap_apsc_flow
        import ap_setting_flow
        import ap_registration
        import ap_xrefs
        import ap_builder_emulation
        import cp_dispatch_emulation
        import cp_check_emulation
        import cp_snapshot_emulation
        import cp_imager_emulation
        ap_bytes, cp_bytes = ap.read_bytes(), cp.read_bytes()
        mpr_bytes = original['files']['libmpr.so'].read_bytes()
        for event, evidence in (
            ('osal_transport_boundary', osal_transport.inspect(original['files']['libosal_uipc.so'].read_bytes())),
            ('ap_xrefs', ap_xrefs.inspect(ap_bytes)),
            ('cp_geometry_lookup_original', cp_stream_geometry.run_geometry_lookup(cp_bytes)),
            ('codec_profile_pin_original', avbbc_receiver.run_profile_pin(mpr_bytes,original['files']['libInfraAvbbc.so'].read_bytes())),
            ('ap_pin_topology_static', avbbc_receiver.inspect_ap_topology(ap_bytes)),
            ('kernel_queue_boundary_static', avbbc_receiver.inspect_kernel(original['files']['osal_uipc.ko'].read_bytes())),
            ('dataflow_pin_transport_static', avbbc_receiver.inspect_dataflow(original['files']['dataflowInfraFramework.so'].read_bytes())),
            ('avbbc_receiver_static', avbbc_receiver.inspect(original['files']['libInfraAvbbc.so'].read_bytes())),
            ('avbbc_receiver_original', avbbc_receiver.run_original(original['files']['libInfraAvbbc.so'].read_bytes())),
            ('mpr_codec_transport_static', mpr_codec_transport.inspect(mpr_bytes)),
            ('mpr_codec_transport_original', mpr_codec_transport.run_original(mpr_bytes)),
            ('cp_movie_geometry_static', cp_movie_geometry.inspect(cp_bytes)),
            ('cp_movie_geometry_original', cp_movie_geometry.run_original(cp_bytes)),
            ('cp_stream_geometry_static', cp_stream_geometry.inspect(cp_bytes)),
            ('cp_stream_geometry_original', cp_stream_geometry.run_original(cp_bytes)),
            ('cp_lowres_route_static', cp_lowres_route.inspect(cp_bytes)),
            ('cp_lowres_route_original', cp_lowres_route.run_original(cp_bytes)),
            ('cp_builder_category_original', cp_request_handoff.run_builder_gate(cp_bytes)),
            ('cp_stage_receiver_original', cp_request_handoff.run_stage_receiver(cp_bytes)),
            ('cp_request_queue_dispatch', cp_request_handoff.run_queue_dispatch(cp_bytes)),
            ('cp_request_handoff_static', cp_request_handoff.inspect(cp_bytes)),
            ('cp_request_handoff_original', cp_request_handoff.run_copies(cp_bytes)),
            ('cp_default_timing_static', cp_timing_compare.inspect(cp_bytes)),
            ('cp_default_timing_original', cp_timing_compare.run_original(cp_bytes)),
            ('cp_availability_init_static', cp_availability_init.inspect(cp_bytes)),
            ('cp_availability_init_fragments', cp_availability_init.run_original(cp_bytes)),
            ('cp_movie_selector_static', cp_movie_selector.inspect(cp_bytes)),
            ('cp_movie_selector_fragments', cp_movie_selector.run_original(cp_bytes)),
            ('cp_rate_projection_fragments', cp_movie_selector.run_rate_projection(cp_bytes)),
            ('cp_selector_fields_static', cp_selector_fields.inspect(cp_bytes)),
            ('cp_selector_fields_fragment', cp_selector_fields.run_original(cp_bytes)),
            ('cp_mode_sequence_static', cp_mode_sequence.inspect(cp_bytes)),
            ('cp_mode_sequence_fragments', cp_mode_sequence.run_original(cp_bytes)),
            ('cp_selector_state_static', cp_selector_state.inspect(cp_bytes)),
            ('cp_selector_state_fragments', cp_selector_state.run_original(cp_bytes)),
            ('mpr_bitrate_static', mpr_bitrate.inspect(mpr_bytes)),
            ('mpr_bitrate_original', mpr_bitrate.run_original(mpr_bytes)),
            ('mpr_target_parameter_chain', mpr_bitrate.run_parameter_chain(ap_bytes,mpr_bytes)),
            ('ap_mpr_encoding_static', ap_mpr_encoding.inspect(ap_bytes)),
            ('ap_mpr_encoding_original', ap_mpr_encoding.run_original(ap_bytes)),
            ('ap_mpr_quality_static', ap_mpr_quality.inspect(ap_bytes)),
            ('ap_mpr_quality_original', ap_mpr_quality.run_original(ap_bytes)),
            ('movie_setting_static_flow', movie_setting_flow.inspect(ap_bytes,cp_bytes)),
            ('movie_ap_fragments', movie_setting_flow.run_ap_original(ap_bytes)),
            ('movie_cp_fragments', movie_setting_flow.run_cp_original(cp_bytes)),
            ('ap_apsc_static_flow', ap_apsc_flow.inspect(ap_bytes)),
            ('ap_apsc_menu_value_fragment', ap_apsc_flow.run_menu_values_original(ap_bytes)),
            ('ap_apsc_builder', ap_apsc_flow.run_original(ap_bytes)),
            ('cp_apsc_policy_fragments', cp_imager_emulation.run_original(cp_bytes,message_id=0x40a2)),
            ('ap_setting_static_flow', ap_setting_flow.inspect(ap_bytes)),
            ('ap_notification_fragments', ap_setting_flow.run_original(ap_bytes)),
            ('ap_registration', ap_registration.inspect(ap_bytes)),
            ('ap_registration_fragments', ap_registration.run_original(ap_bytes)),
            ('ap_rate_predicates', ap_registration.run_rate_original(ap_bytes)),
            ('ap_builder_prefix', ap_builder_emulation.run_original(ap_bytes)),
            ('cp_dispatch_prefix', cp_dispatch_emulation.run_original(cp_bytes)),
            ('cp_state_lifecycle', cp_dispatch_emulation.run_state_lifecycle_original(cp_bytes)),
            ('cp_handler_fragments', cp_imager_emulation.run_original(cp_bytes)),
            ('cp_initialization_snapshot', cp_snapshot_emulation.run_original(cp_bytes)),
            ('cp_check_callback', cp_check_emulation.run_original(cp_bytes)),
        ):
            print(json.dumps({'event': event, 'evidence': evidence}, indent=2), flush=True)
        env = dict(os.environ, A7C2_VIDEO_CP_REFERENCE=str(cp),
                   A7C2_VIDEO_KERNEL_REFERENCE=str(original['files']['osal_uipc.ko']),
                   A7C2_VIDEO_DATAFLOW_REFERENCE=str(original['files']['dataflowInfraFramework.so']),
                   A7C2_VIDEO_AVBBC_REFERENCE=str(original['files']['libInfraAvbbc.so']),
                   A7C2_VIDEO_AP_REFERENCE=str(ap), A7C2_VIDEO_MPR_REFERENCE=str(original['files']['libmpr.so']),
                   PYTHONDONTWRITEBYTECODE='1')
        for optimization in ([], ['-O']):
            subprocess.run([sys.executable, *optimization, '-B', '-m', 'unittest',
                            'discover', '-s', 'dev/video_research', '-v'],
                           cwd=ROOT, env=env, check=True)
        print('Official-reference integration completed; no camera or firmware writes.', flush=True)
    print('Temporary official package and extracted components removed.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
