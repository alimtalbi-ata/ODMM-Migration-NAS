"""Read-only local inventory for desktop planning; NOT an ACL or NAS fidelity certificate."""
import hashlib
import os
import stat
from pathlib import Path

MAX_FILES = 10000

def inspect_local_source(source, target, *, limit=MAX_FILES):
    """Never writes or follows symlinks; rejects unsupported entries and overlap."""
    if not isinstance(limit, int) or not 1 <= limit <= MAX_FILES:
        raise ValueError('INVALID_LIMIT')
    roots = [Path(os.path.abspath(os.fspath(p))) for p in (source, target)]
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError('INVALID_OR_SYMLINK_ROOT')
    src, dst = [p.resolve(strict=True) for p in roots]
    if src == dst or src in dst.parents or dst in src.parents:
        raise ValueError('OVERLAPPING_ROOTS')
    entries = []
    total = 0
    issues = []
    for base, dirs, files in os.walk(src, followlinks=False):
        for name in sorted(dirs):
            p = Path(base) / name
            if p.is_symlink():
                issues.append({'path': p.relative_to(src).as_posix(), 'issue': 'SYMLINK_DIRECTORY'})
        dirs[:] = sorted(d for d in dirs if not (Path(base) / d).is_symlink())
        for name in sorted(files):
            p = Path(base) / name
            rel = p.relative_to(src).as_posix()
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode):
                issues.append({'path': rel, 'issue': 'UNSUPPORTED_ENTRY'})
                continue
            if len(entries) >= limit:
                raise ValueError('INVENTORY_LIMIT_REACHED')
            if (dst / rel).exists() or (dst / rel).is_symlink():
                issues.append({'path': rel, 'issue': 'DESTINATION_EXISTS'})
            entries.append({'path': rel, 'bytes': st.st_size, 'mode': oct(stat.S_IMODE(st.st_mode))})
            total += st.st_size
    return {'status': 'BLOCKED' if issues else 'PRECHECK_ONLY', 'source': str(src), 'target': str(dst), 'files': len(entries), 'bytes': total, 'entries': entries, 'issues': issues, 'note': 'Read-only POSIX-style inventory; no migration, ACL fidelity or cutover authorization.'}
