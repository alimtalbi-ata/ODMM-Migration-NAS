"""Verify an existing Windows release without rewriting its evidence."""
import hashlib, json, sys
from pathlib import Path

def validate(root):
    root=Path(root)
    manifest=json.loads((root/'SHA256-WINDOWS.json').read_text(encoding='utf-8'))
    status=json.loads((root/'BUILD-STATUS.json').read_text(encoding='utf-8'))
    version=status.get('version')
    if status.get('build')!='completed' or not isinstance(version,str) or not version:
        raise ValueError('Release status is not completed')
    names={'portable/ODMM-Compact.exe',f'installer/ODMM-Compact-Setup-V{version}.exe'}
    entries=manifest.get('artifacts')
    if not isinstance(entries,list) or len(entries)!=2 or {e.get('file') for e in entries}!=names:
        raise ValueError('Release manifest does not contain both expected artifacts')
    if status.get('artifacts')!=entries:
        raise ValueError('Status and checksum manifests disagree')
    for entry in entries:
        rel=entry['file']; path=root/rel
        if not path.is_file() or path.stat().st_size!=entry.get('size') or path.stat().st_size<1024:
            raise ValueError('Missing or incorrectly sized artifact: '+rel)
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest!=entry.get('sha256'):
            raise ValueError('Checksum mismatch: '+rel)
        with path.open('rb') as f:
            if f.read(2)!=b'MZ': raise ValueError('Missing MZ signature: '+rel)
            f.seek(0x3c); offset=int.from_bytes(f.read(4),'little')
            if offset<64 or offset>path.stat().st_size-24: raise ValueError('Invalid PE offset: '+rel)
            f.seek(offset)
            if f.read(4)!=b'PE\x00\x00': raise ValueError('Invalid PE signature: '+rel)
    return version

if __name__=='__main__':
    try: print('VALID RELEASE:',validate(sys.argv[1]))
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as e:
        print('INVALID RELEASE:',e,file=sys.stderr);sys.exit(1)
