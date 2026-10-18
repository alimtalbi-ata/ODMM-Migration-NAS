"""Portable procedure qualification, non-destructive. Author: Abdelhalim Talbi."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REQUIRED = ('odmm_portable_doctor_v2246.py', 'ODMM-PORTABLE-CHECK.sh', 'ODMM-PORTABLE-CHECK.cmd')

def qualify(root: Path, *, run_smoke=True):
    root = Path(root).resolve()
    findings = []
    checks = []
    for name in REQUIRED:
        ok = (root / name).is_file()
        checks.append({'procedure': f'file:{name}', 'status': 'PASS' if ok else 'FAIL'})
        if not ok:
            findings.append(f'MISSING:{name}')
    if run_smoke and not findings:
        # Never execute arbitrary files in the original project: isolated copy, read-only audit.
        with tempfile.TemporaryDirectory(prefix='odmm-portable-qualification-') as tmp:
            isolated = Path(tmp)
            for name in REQUIRED:
                shutil.copy2(root / name, isolated / name)
            command = [sys.executable, str(isolated / REQUIRED[0]), '--root', str(isolated), '--output', str(isolated / 'report.json')]
            try:
                process = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                report = json.loads((isolated / 'report.json').read_text(encoding='utf-8')) if (isolated / 'report.json').exists() else {}
                ok = process.returncode == 0 and report.get('status') == 'PASS' and report.get('python_checked') == 1
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                ok = False
                findings.append(f'SMOKE_EXCEPTION:{type(exc).__name__}')
            checks.append({'procedure': 'isolated-python-preflight', 'status': 'PASS' if ok else 'FAIL'})
            if not ok:
                findings.append('PORTABLE_SMOKE_FAILED')
            if os.name != 'nt':
                try:
                    shell = subprocess.run(['sh', str(isolated / 'ODMM-PORTABLE-CHECK.sh')], cwd=isolated,
                                           capture_output=True, text=True, timeout=30, check=False)
                    shell_report = json.loads((isolated / 'odmm-portable-report.json').read_text(encoding='utf-8'))
                    shell_ok = shell.returncode == 0 and shell_report.get('status') == 'PASS'
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    shell_ok = False
                checks.append({'procedure': 'isolated-linux-launcher', 'status': 'PASS' if shell_ok else 'FAIL'})
                if not shell_ok:
                    findings.append('LINUX_LAUNCHER_FAILED')
    checks.append({'procedure': 'windows-native-execution', 'status': 'NOT_TESTED' if os.name != 'nt' else 'NOT_TESTED'})
    checks.append({'procedure': 'nas-migration-e2e', 'status': 'NOT_TESTED'})
    return {'version': '224.7', 'author': 'Abdelhalim Talbi', 'checks': checks,
            'findings': findings, 'status': 'FAIL' if findings else 'PASS_WITH_UNQUALIFIED_ITEMS',
            'scope': 'Isolated portable preflight only; not an application or migration end-to-end test'}

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    result = qualify(args.root)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered)
    return 1 if result['findings'] else 0

if __name__ == '__main__':
    raise SystemExit(main())
