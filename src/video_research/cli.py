"""Standard-library-only CLI. Only an explicitly requested JSON report is written."""
import argparse
import json
import os
from pathlib import Path
import sys

from .inventory import inspect_images
from .planner import PROFILES, plan
from .reference import catalog

GUIDE = '''
Examples / 示例:
  python video_research.py catalog
  python video_research.py inventory --cp /local/cpapp-b.bin --ap /local/appFw.so
  python video_research.py plan --profile ff4k60 --cp /local/cpapp-b.bin
  python video_research.py plan --profile 4k120

Use lawful, original ILCE-7CM2 2.01 components. FL23/custom images are not the
reference for this parser; existing installers are unchanged. No firmware is
bundled or downloaded. Reports contain local derived evidence; keep them private.
输出仅为离线研究报告，不是解锁补丁；不会连接相机，不会修改固件。
Exit 0 means a report was produced, NOT installation or hardware acceptance.
Exit 2 means invalid arguments, incompatible input or a local I/O error.
'''


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description='A7C II video research: OFFLINE ONLY / 仅离线分析',
                                   epilog=GUIDE, formatter_class=argparse.RawDescriptionHelpFormatter)
    subs = root.add_subparsers(dest='command', required=True)
    for name, help_text in (
            ('catalog', 'Published references without firmware files / 查看公开研究基线'),
            ('inventory', 'Inspect original local CP/AP files read-only / 只读解析原始固件'),
            ('plan', 'Generate an evidence-gap plan, never a patch / 生成验证缺口清单')):
        sub = subs.add_parser(name, help=help_text)
        sub.add_argument('--output', type=Path, help='New *.private.json file; parent must exist; never overwritten')
        if name != 'catalog':
            sub.add_argument('--cp', type=Path, required=name == 'inventory', help='Original 2.01 cpapp-b.bin')
            sub.add_argument('--ap', type=Path, help='Optional original 2.01 appFw.so (identity only)')
        if name == 'plan':
            sub.add_argument('--profile', choices=PROFILES, required=True)
    return root


def emit(report: dict, output: Path | None, inputs: tuple[Path, ...] = ()) -> None:
    payload = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    if output is None:
        print(payload, end='')
        return
    if not output.name.endswith('.private.json'):
        raise ValueError('Report filename must end with .private.json; no firmware outputs are supported.')
    if any(output.resolve() == item.resolve() for item in inputs):
        raise ValueError('Report output must not alias an input file.')
    # Windows CRT O_EXCL can follow a dangling destination symlink. lstat
    # rejects an existing entry early; hard-link creation is the atomic,
    # no-overwrite publication guard if another process creates it afterward.
    # Fail closed on filesystems without hard links; never fall back to rename.
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError('Report destination already exists.')
    temporary = output.parent/('.a7c2-video-' + os.urandom(16).hex() + '.private.json')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
    finally:
        # Only remove our temporary file, never a concurrent job's destination.
        temporary.unlink(missing_ok=True)



def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        inputs = tuple(p for p in (getattr(args, 'cp', None), getattr(args, 'ap', None)) if p is not None)
        if args.command == 'catalog':
            report, failed = catalog(), False
        else:
            inventory = inspect_images(args.cp, args.ap)
            failed = bool(inventory['errors'])
            report = plan(args.profile, inventory) if args.command == 'plan' else inventory
            if args.command == 'plan' and failed:
                report['input_errors'] = inventory['errors']
        emit(report, args.output, inputs)
        return 2 if failed else 0
    except (OSError, ValueError) as exc:
        # No absolute user paths, raw firmware bytes or local filenames in logs.
        reason = str(exc) if isinstance(exc, ValueError) else 'Local I/O failed: ' + type(exc).__name__
        print(json.dumps(dict(schema='a7c2-video-error/1', error=reason,
                              camera_io=False, firmware_written=False), ensure_ascii=False), file=sys.stderr)
        return 2
