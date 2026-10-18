"""Bounded read-only ACL evidence collection, not a NAS cutover approval.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from pathlib import Path
import os
import stat
import subprocess
from odmm_acl_protocol_v2177 import parse_protocol_acl, ProtocolACLError

@dataclass(frozen=True)
class ACLCapture:
    evidence: object
    source: str
    read_only: bool = True
    effective_access_verified: bool = False
    cutover_authorized: bool = False

def _regular_file(path):
    p = Path(path)
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 262144:
            raise ProtocolACLError('UNSAFE_EVIDENCE_FILE')
        data = os.read(fd, 262145)
        if len(data) > 262144:
            raise ProtocolACLError('EVIDENCE_TOO_LARGE')
        return data
    finally:
        os.close(fd)

def collect_canonical_file(protocol, path, *, collector='canonical_file'):
    """Import a pre-normalized read-only report; NOT a live SMB/NFS collector."""
    if protocol not in ('SMB', 'NFSv4'):
        raise ProtocolACLError('UNSUPPORTED_PROTOCOL')
    return ACLCapture(parse_protocol_acl(protocol, collector, _regular_file(path)), str(path))

def collect_nfsv4_local(path, *, executable='/usr/bin/nfs4_getfacl', timeout=5):
    """Read NFSv4 ACL of an existing local mount without shell execution.

    Caller must supply an approved local mount path; never uses remote credentials.
    """
    p = Path(path)
    if not p.is_absolute() or p.is_symlink() or not p.exists():
        raise ProtocolACLError('UNSAFE_TARGET')
    if executable != '/usr/bin/nfs4_getfacl' or not 0 < timeout <= 30:
        raise ProtocolACLError('UNAPPROVED_COLLECTOR')
    try:
        result = subprocess.run([executable, '--', str(p)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolACLError('COLLECTION_FAILED') from exc
    if result.returncode or len(result.stdout) > 262144:
        raise ProtocolACLError('COLLECTION_FAILED')
    # nfs4_getfacl emits comment headers; retain only strict ACE lines.
    lines = [line for line in result.stdout.splitlines() if line and not line.startswith(b'#')]
    return ACLCapture(parse_protocol_acl('NFSv4', 'nfs4_getfacl', b'\n'.join(lines)), str(p))
