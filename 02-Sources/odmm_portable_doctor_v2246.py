"""ODMM portable preflight, read-only. Author: Abdelhalim Talbi."""
from __future__ import annotations
import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

OPTIONAL_RUNTIME = ('fastapi', 'uvicorn', 'cryptography', 'httpx', 'pydantic')
EXCLUDED = {'.git', '.venv', 'venv', '__pycache__', 'node_modules'}


def audit(root: Path, *, check_imports=True):
    root = root.resolve()
    findings = []
    scripts = []
    for path in sorted(root.rglob('*')):
        if any(part in EXCLUDED for part in path.relative_to(root).parts) or not path.is_file():
            continue
        if path.suffix.lower() not in {'.py', '.cmd', '.bat', '.sh', '.ps1'}:
            continue
        rel = path.relative_to(root).as_posix()
        scripts.append(rel)
        if path.suffix.lower() == '.py':
            try:
                ast.parse(path.read_text(encoding='utf-8-sig'), filename=rel)
            except (SyntaxError, UnicodeError, OSError) as exc:
                findings.append({'file': rel, 'code': 'PYTHON_PARSE_ERROR', 'detail': str(exc)[:300]})
    missing = [name for name in OPTIONAL_RUNTIME if importlib.util.find_spec(name) is None] if check_imports else []
    for name in missing:
        findings.append({'file': '', 'code': 'RUNTIME_DEPENDENCY_MISSING', 'detail': name})
    launchers = [p for p in scripts if p.lower().endswith(('.cmd', '.bat', '.sh'))]
    return {
        'version': '224.6', 'author': 'Abdelhalim Talbi',
        'host': {'system': platform.system(), 'python': platform.python_version(), 'architecture': platform.machine()},
        'root': str(root), 'scripts_checked': len(scripts),
        'python_checked': sum(p.endswith('.py') for p in scripts),
        'launchers': launchers, 'findings': findings,
        'status': 'PASS' if not findings else 'FAIL',
        'qualification': 'Local syntax/dependency preflight only; no Windows/NAS/OIDC live validation',
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='ODMM portable diagnostic (read-only)')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    result = audit(args.root)
    content = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content + '\n', encoding='utf-8')
    print(content)
    return 0 if result['status'] == 'PASS' else 1

if __name__ == '__main__':
    sys.exit(main())
