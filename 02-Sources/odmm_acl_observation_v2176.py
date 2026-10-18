"""Read-only POSIX ACL observation; never certifies NFSv4/SMB rights.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import subprocess

class ACLObservationError(RuntimeError):
    pass

@dataclass(frozen=True)
class ACLObservation:
    path: str
    entries: tuple[str, ...]
    owner: int
    group: int
    mode: int
    provenance: str = 'LOCAL_POSIX_GETFACL'
    effective_access_verified: bool = False
    vendor_qualified: bool = False


def observe_posix(path, *, timeout=5, max_bytes=262144, runner=subprocess.run):
    """Read a local regular file's ACL without following symbolic links.

    This is a diagnostic observation, NOT NFSv4/SMB ACL equivalence.
    """
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ACLObservationError('UNSAFE_OR_NONREGULAR_SOURCE')
    tool = shutil.which('getfacl')
    if tool is None:
        raise ACLObservationError('GETFACL_UNAVAILABLE')
    before = os.lstat(p)
    if not os.path.isfile(p) or before.st_nlink < 1:
        raise ACLObservationError('SOURCE_CHANGED')
    try:
        result = runner([tool, '--absolute-names', '--', str(p)], capture_output=True,
                        timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ACLObservationError('ACL_COLLECTION_FAILED') from exc
    if result.returncode != 0 or len(result.stdout) > max_bytes:
        raise ACLObservationError('ACL_COLLECTION_FAILED')
    after = os.lstat(p)
    if (before.st_dev, before.st_ino, before.st_ctime_ns, before.st_mode) != (after.st_dev, after.st_ino, after.st_ctime_ns, after.st_mode):
        raise ACLObservationError('SOURCE_CHANGED')
    try:
        lines = result.stdout.decode('utf-8', errors='strict').splitlines()
    except UnicodeError as exc:
        raise ACLObservationError('ACL_ENCODING_INVALID') from exc
    entries = tuple(sorted(x.strip() for x in lines if x.strip() and not x.startswith('#')))
    if not entries or not all(':' in x for x in entries):
        raise ACLObservationError('ACL_OUTPUT_INVALID')
    return ACLObservation(str(p), entries, before.st_uid, before.st_gid, before.st_mode & 0o7777)


def compare_posix(source: ACLObservation, target: ACLObservation):
    """Compare local POSIX observations; never asserts vendor equivalence."""
    if source.provenance != 'LOCAL_POSIX_GETFACL' or target.provenance != 'LOCAL_POSIX_GETFACL':
        raise ACLObservationError('INCOMPATIBLE_ACL_PROVENANCE')
    return {'acl_entries_equal': source.entries == target.entries,
            'uid_equal': source.owner == target.owner,
            'gid_equal': source.group == target.group,
            'mode_equal': source.mode == target.mode,
            'effective_access_verified': False,
            'nas_cutover_authorized': False}
