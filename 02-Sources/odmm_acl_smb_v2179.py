"""Read-only SMB ACL observation through smbcacls; strict subset, no cutover. Author: Abdelhalim Talbi."""
from dataclasses import dataclass
import re
import subprocess
from odmm_acl_protocol_v2177 import parse_protocol_acl, ProtocolACLError
from odmm_acl_collect_v2178 import ACLCapture

_SID = re.compile(r'^ACL:(S-1-(?:\d+-){1,14}\d+):(ALLOWED|DENIED)/0x([0-9a-fA-F]+)/([A-Z_,]+)$')
_ALLOWED = {'READ', 'WRITE', 'FULL', 'CHANGE', 'READ_CONTROL', 'DELETE', 'WRITE_DAC', 'WRITE_OWNER', 'EXECUTE'}

def normalize_smbcacls(raw: bytes) -> bytes:
    """Reject unresolved names and unsupported ACE flags/rights rather than misrepresenting them."""
    if not raw or len(raw) > 262144 or b'\x00' in raw:
        raise ProtocolACLError('INVALID_SMB_OUTPUT')
    try:
        lines = raw.decode('utf-8', 'strict').splitlines()
    except UnicodeError as exc:
        raise ProtocolACLError('INVALID_SMB_ENCODING') from exc
    entries = []
    for line in lines:
        if line.startswith('ACL:'):
            m = _SID.fullmatch(line)
            if not m or int(m.group(3), 16) != 0:
                raise ProtocolACLError('UNSUPPORTED_SMB_ACE')
            rights = m.group(4).split(',')
            if not rights or any(r not in _ALLOWED for r in rights) or len(set(rights)) != len(rights):
                raise ProtocolACLError('UNSUPPORTED_SMB_RIGHTS')
            entries.append(f"{'ALLOW' if m.group(2)=='ALLOWED' else 'DENY'}|{m.group(1)}|{','.join(rights)}|EXPLICIT")
        elif line.startswith(('REVISION:', 'OWNER:', 'GROUP:')):
            continue
        else:
            raise ProtocolACLError('UNRECOGNIZED_SMB_OUTPUT')
    if not entries:
        raise ProtocolACLError('NO_SMB_ACE')
    return '\n'.join(entries).encode('utf-8')

def collect_smb_remote(share: str, path: str, *, executable='/usr/bin/smbcacls', timeout=5, credentials_file=None):
    """Collect SID ACLs, read-only. Credentials via protected file, never argv secrets."""
    if executable != '/usr/bin/smbcacls' or not 0 < timeout <= 30:
        raise ProtocolACLError('UNAPPROVED_COLLECTOR')
    if not re.fullmatch(r'//[A-Za-z0-9_.-]+/[A-Za-z0-9_$.-]+', share):
        raise ProtocolACLError('UNSAFE_SHARE')
    if not path or path.startswith(('/', '\\')) or any(p in ('', '.', '..') for p in path.replace('\\','/').split('/')) or any(ord(c)<32 for c in path):
        raise ProtocolACLError('UNSAFE_PATH')
    args = [executable, share, path, '-n']
    if credentials_file is not None:
        import os, stat
        fd = os.open(credentials_file, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
                raise ProtocolACLError('UNSAFE_CREDENTIALS')
        finally:
            os.close(fd)
        args += ['-A', str(credentials_file)]
    try:
        r = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolACLError('SMB_COLLECTION_FAILED') from exc
    if r.returncode != 0:
        raise ProtocolACLError('SMB_COLLECTION_FAILED')
    normalized = normalize_smbcacls(r.stdout)
    return ACLCapture(parse_protocol_acl('SMB', 'smbcacls', normalized), share+'/'+path)
