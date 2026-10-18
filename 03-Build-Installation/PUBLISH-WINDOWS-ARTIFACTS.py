"""Directory-level release promotion with rollback; Windows rename limitations apply."""
import os, sys, shutil
from pathlib import Path

def publish(stage, destination, version):
    stage, destination = Path(stage), Path(destination)
    expected = [stage/'portable'/'ODMM-Compact.exe', stage/'installer'/f'ODMM-Compact-Setup-V{version}.exe', stage/'SHA256-WINDOWS.json', stage/'BUILD-STATUS.json']
    if not all(p.is_file() for p in expected):
        raise RuntimeError('Missing verified build artifact; publication refused')
    parent = destination.parent
    candidate = parent/(destination.name+'.next')
    backup = parent/(destination.name+'.previous')
    if candidate.exists(): shutil.rmtree(candidate)
    shutil.copytree(stage, candidate)
    if not all((candidate/p.relative_to(stage)).is_file() for p in expected):
        shutil.rmtree(candidate)
        raise RuntimeError('Incomplete staged copy')
    if backup.exists(): shutil.rmtree(backup)
    had_previous = destination.exists()
    if had_previous: os.replace(destination, backup)
    try:
        os.replace(candidate, destination)
    except BaseException:
        if had_previous and backup.exists(): os.replace(backup, destination)
        raise
    # Keep backup until next successful build for operator recovery.

if __name__ == '__main__': publish(sys.argv[1],sys.argv[2],sys.argv[3])
