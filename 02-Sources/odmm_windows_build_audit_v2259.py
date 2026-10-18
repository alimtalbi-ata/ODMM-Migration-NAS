"""Read-only Windows build prerequisite and artifact auditor."""
import argparse, hashlib, json, pathlib, platform, shutil, sys, zipfile

REQUIRED = ('odmm_windows_desktop_v2258.py', 'odmm_desktop_model_v2258.py', 'ODMM-WINDOWS-V2259.iss', 'BUILD-WINDOWS-V2259.cmd')
def audit(root, artifacts=False):
    root = pathlib.Path(root)
    checks = {name: (root / name).is_file() for name in REQUIRED}
    checks['python_3_10_plus'] = sys.version_info >= (3, 10)
    checks['pyinstaller_available'] = __import__('importlib').util.find_spec('PyInstaller') is not None
    checks['windows_host'] = platform.system() == 'Windows'
    checks['inno_setup_found'] = bool(shutil.which('ISCC') or (root / 'ISCC.exe').is_file())
    if artifacts:
        checks['portable_exe'] = (root/'dist'/'ODMM-Desktop.exe').is_file()
        checks['installer_exe'] = (root/'dist'/'ODMM-Setup-V225.9.exe').is_file()
    return {'version':'V225.9', 'checks':checks, 'ready_for_windows_build':all(checks[k] for k in REQUIRED) and checks['python_3_10_plus'] and checks['windows_host'], 'windows_build_executed':bool(artifacts and checks.get('portable_exe') and checks.get('installer_exe')), 'artifacts':{n:hashlib.sha256((root/'dist'/n).read_bytes()).hexdigest() for n in ('ODMM-Desktop.exe','ODMM-Setup-V225.9.exe') if (root/'dist'/n).is_file()}}
if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',default='.');p.add_argument('--artifacts',action='store_true');p.add_argument('--output');a=p.parse_args();r=audit(a.root,a.artifacts);s=json.dumps(r,indent=2,ensure_ascii=False);print(s)
    if a.output:pathlib.Path(a.output).write_text(s+'\n',encoding='utf-8')
