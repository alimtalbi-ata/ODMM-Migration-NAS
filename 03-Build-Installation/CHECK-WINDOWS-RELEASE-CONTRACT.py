"""Fail fast on Windows release version drift. Pure stdlib, no Windows required."""
from pathlib import Path
import argparse,re,sys

def check(root: Path):
    cmd=(root/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text(encoding='utf-8')
    wf=(root/'.github/workflows/windows-compact-release.yml').read_text(encoding='utf-8')
    match=re.search(r'^set "ODMM_VERSION=(\d+\.\d+\.\d+)"',cmd,re.M)
    if not match: raise ValueError('Build version declaration missing')
    version=match.group(1)
    for token in (f'ODMM-Compact-Setup-V{version}.exe', f"-Version '{version}'"):
        if token not in wf: raise ValueError(f'Workflow does not match build version: {token}')
    if 'windows-2022' not in wf: raise ValueError('Native Windows runner missing')
    if 'VALIDATE-WINDOWS-RELEASE.py binary' not in wf: raise ValueError('Artifact validation missing')
    if 'TEST-WINDOWS-INSTALL.ps1' not in wf: raise ValueError('Install smoke test missing')
    return version

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    args=p.parse_args()
    try: print('Windows release contract OK:',check(args.root))
    except (ValueError,OSError) as e: print('ERROR:',e,file=sys.stderr);sys.exit(1)
