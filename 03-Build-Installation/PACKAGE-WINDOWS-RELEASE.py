"""Package a qualified Windows build, preserving the complete cumulative source tree."""
import argparse
from pathlib import Path
import zipfile
import sys
import hashlib
import json

SKIP_DIRS={'.git','.windows-build-venv','.windows-build-stage','binary.previous','__pycache__'}

def package(root, output):
    root=Path(root).resolve(); output=Path(output).resolve()
    sys.path.insert(0,str(root/'03-Build-Installation'))
    from importlib import import_module
    validator=import_module('VALIDATE-WINDOWS-RELEASE')
    validator.validate(root/'binary')
    portable=root/'binary/portable/ODMM-Compact.exe'
    installers=list((root/'binary/installer').glob('ODMM-Compact-Setup-V*.exe'))
    if not portable.is_file() or len(installers)!=1:
        raise ValueError('Exactly one qualified installer and one portable executable required')
    if not (root/'binary/WINDOWS-INSTALL-SMOKE.json').exists():
        raise ValueError('Missing native install/uninstall smoke report')
    import json
    report=json.loads((root/'binary/WINDOWS-INSTALL-SMOKE.json').read_text(encoding='utf-8'))
    if not all(report.get(k) is True for k in ('passed','installed','uninstalled')):
        raise ValueError('Native install/uninstall tests not passed')
    provenance=root/'binary/WINDOWS-RUNNER-INFO.json'
    if not provenance.is_file():
        raise ValueError('Missing native Windows runner provenance')
    runner=json.loads(provenance.read_text(encoding='utf-8'))
    if not runner.get('run_id') or not runner.get('commit'):
        raise ValueError('Incomplete native Windows runner provenance')
    output.parent.mkdir(parents=True,exist_ok=True)
    digests = {}
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for f in sorted(root.rglob('*')):
            if not f.is_file() or f.resolve()==output: continue
            rel=f.relative_to(root)
            if any(part in SKIP_DIRS for part in rel.parts) or rel.suffix in ('.pyc','.pyo'):continue
            name = rel.as_posix()
            if name == 'DELIVERY-MANIFEST.json':
                continue
            z.write(f,name)
            with f.open('rb') as stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            digests[name] = digest.hexdigest()
        manifest = {
            'schema_version': 1,
            'source_type': 'windows-qualified-git-checkout',
            'source_commit': runner['commit'],
            'windows_run_id': str(runner['run_id']),
            'qualification': {
                'windows_install_smoke': 'PASS',
                'windows_uninstall_smoke': 'PASS',
                'runner': 'windows-2022',
            },
            'files': digests,
        }
        z.writestr('DELIVERY-MANIFEST.json', json.dumps(manifest, indent=2, sort_keys=True) + '\\n')
    with zipfile.ZipFile(output) as z:
        if z.testzip() is not None:raise ValueError('ZIP CRC failed')
        for path in ('binary/portable/ODMM-Compact.exe', 'binary/WINDOWS-INSTALL-SMOKE.json', 'binary/WINDOWS-RUNNER-INFO.json', 'binary/SHA256-WINDOWS.json') :
            if path not in z.namelist():raise ValueError('Missing '+path)
    return output

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',default='.');p.add_argument('--output',required=True)
    a=p.parse_args();print(package(a.root,a.output))
