"""Audit the actual release artifacts, never report a stale version."""
import argparse, hashlib, json, pathlib, platform, sys
REQUIRED = ('odmm_windows_desktop_v2273.py', 'odmm_desktop_async_v2273.py', 'ODMM-WINDOWS-V2273.iss', 'BUILD-WINDOWS-V2273.cmd')
ARTIFACTS = ('ODMM-Desktop.exe','ODMM-Setup-V227.3.exe')
def audit(root, artifacts=False):
    root = pathlib.Path(root)
    checks = {name:(root/name).is_file() for name in REQUIRED}
    checks['python_3_10_plus'] = sys.version_info >= (3,10)
    checks['windows_host'] = platform.system() == 'Windows'
    if artifacts:
        checks.update({name:(root/'dist'/name).is_file() for name in ARTIFACTS})
    return {'version':'V227.3','checks':checks,'windows_build_executed': bool(artifacts and all(checks.get(n) for n in ARTIFACTS)), 'artifacts':{n:hashlib.sha256((root/'dist'/n).read_bytes()).hexdigest() for n in ARTIFACTS if (root/'dist'/n).is_file()}}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',default='.');p.add_argument('--artifacts',action='store_true');p.add_argument('--output');args=p.parse_args()
    result=audit(args.root,args.artifacts);output=json.dumps(result,indent=2);print(output)
    if args.output:pathlib.Path(args.output).write_text(output+'\n',encoding='utf8')
    if args.artifacts and not result['windows_build_executed']:sys.exit(1)
