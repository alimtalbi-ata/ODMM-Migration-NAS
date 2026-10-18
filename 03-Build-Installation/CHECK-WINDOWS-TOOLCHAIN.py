"""ODMM V228.68: non-destructive Windows build toolchain diagnostics."""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def inspect_toolchain(iscc: str, python: str = sys.executable) -> dict:
    checks = {
        'windows_host': os.name == 'nt',
        'python_64bit': sys.maxsize > 2**32,
        'python_supported': sys.version_info >= (3, 10),
        'inno_compiler_exists': Path(iscc).is_file(),
        'python_exists': Path(python).is_file(),
    }
    for module in ('PyInstaller', 'tkinter'):
        result = subprocess.run([python, '-c', f'import {module}'], capture_output=True, text=True, timeout=30)
        checks[f'{module.lower()}_importable'] = result.returncode == 0
    return {'schema': 1, 'platform': platform.platform(), 'python': python,
            'inno_setup': iscc, 'checks': checks, 'ready': all(checks.values())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iscc', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = inspect_toolchain(args.iscc)
    dest = Path(args.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
    print('Windows toolchain:', 'READY' if report['ready'] else 'NOT READY', str(dest))
    return 0 if report['ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
