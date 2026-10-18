"""Read-only planning inventory. Conservative Windows/SMB compatibility checks, NOT ACL validation."""
import os
import stat
from pathlib import Path

MAX_FILES = 10000
_INVALID = set('<>:"/\\|?*')
_RESERVED = {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}

def windows_name_issue(name):
    if not name or name.endswith((' ', '.')) or any(c in _INVALID or ord(c) < 32 for c in name):
        return 'WINDOWS_UNSAFE_NAME'
    if name.split('.')[0].upper() in _RESERVED:
        return 'WINDOWS_RESERVED_NAME'
    return None

def inspect_local_source(source, target, *, limit=MAX_FILES):
    if type(limit) is not int or not 1 <= limit <= MAX_FILES:
        raise ValueError('INVALID_LIMIT')
    roots=[]
    for raw in (source,target):
        if not os.fspath(raw):
            raise ValueError('EMPTY_ROOT')
        p=Path(os.path.abspath(os.fspath(raw)))
        if p.is_symlink() or not p.is_dir():
            raise ValueError('INVALID_OR_SYMLINK_ROOT')
        roots.append(p.resolve(strict=True))
    src,dst=roots
    if src==dst or src in dst.parents or dst in src.parents:
        raise ValueError('OVERLAPPING_ROOTS')
    issues=[]; entries=[]; total=0; source_keys=set(); dest_keys=set()
    def issue(rel,kind): issues.append({'path':rel,'issue':kind})
    # Inventory destination, including case-insensitive name collisions relevant to Windows/SMB.
    for base, dirs, files in os.walk(dst, followlinks=False):
        for name in dirs+files:
            rel=(Path(base)/name).relative_to(dst).as_posix()
            dest_keys.add(rel.casefold())
        dirs[:]=[d for d in dirs if not (Path(base)/d).is_symlink()]
    for base, dirs, files in os.walk(src, followlinks=False):
        for name in sorted(dirs+files):
            p=Path(base)/name
            rel=p.relative_to(src).as_posix()
            problem=windows_name_issue(name)
            if problem: issue(rel,problem)
            key=rel.casefold()
            if key in source_keys: issue(rel,'CASE_INSENSITIVE_SOURCE_COLLISION')
            source_keys.add(key)
            if key in dest_keys: issue(rel,'DESTINATION_COLLISION_CASE_INSENSITIVE')
            st=p.lstat()
            if stat.S_ISLNK(st.st_mode):
                issue(rel,'SYMLINK_UNSUPPORTED')
            elif stat.S_ISREG(st.st_mode):
                if len(entries)>=limit: raise ValueError('INVENTORY_LIMIT_REACHED')
                entries.append({'path':rel,'bytes':st.st_size,'mode':oct(stat.S_IMODE(st.st_mode))})
                total+=st.st_size
            elif not stat.S_ISDIR(st.st_mode):
                issue(rel,'UNSUPPORTED_ENTRY')
        dirs[:]=sorted(d for d in dirs if not (Path(base)/d).is_symlink())
    return {'status':'BLOCKED' if issues else 'PRECHECK_ONLY','source':str(src),'target':str(dst),'files':len(entries),'bytes':total,'entries':entries,'issues':issues,'note':'Read-only inventory; no ACL/ADS/xattr fidelity, no race-free snapshot, no NAS certification, no cutover authorization.'}
