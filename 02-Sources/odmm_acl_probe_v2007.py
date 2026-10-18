"""Read-only POSIX ACL evidence via getfacl; never assert SMB/NFSv4 equivalence.
Author: Abdelhalim Talbi.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

class ACLProbeError(RuntimeError): pass

def probe(root, relative_path, *, timeout=10, runner=None):
    root=Path(root)
    if root.is_symlink() or not root.is_dir(): raise ACLProbeError('INVALID_ROOT')
    base=root.resolve(strict=True)
    rel=Path(relative_path)
    if rel.is_absolute() or not rel.parts or any(p in ('..','.') for p in rel.parts): raise ACLProbeError('INVALID_PATH')
    target=base/rel
    # Resolve parents, but never follow final symlink.
    if not target.parent.resolve(strict=True).is_relative_to(base): raise ACLProbeError('PATH_ESCAPE')
    if target.is_symlink() or not target.exists(): raise ACLProbeError('INVALID_TARGET')
    tool=shutil.which('getfacl')
    if not tool: return {'status':'NOT_COLLECTED','reason':'GETFACL_NOT_INSTALLED','acl_equivalence_verified':False}
    command=[tool,'--absolute-names','--',str(target)]
    try:
        result=(runner or subprocess.run)(command,capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc: raise ACLProbeError('ACL_PROBE_FAILED') from exc
    if result.returncode: raise ACLProbeError('ACL_PROBE_FAILED')
    # Ignore comments (paths/owner labels), retain order and ACL mask/default ACEs.
    lines=[line.strip() for line in result.stdout.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if not lines: raise ACLProbeError('EMPTY_ACL_EVIDENCE')
    return {'status':'POSIX_ACL_COLLECTED','acl_format':'POSIX_GETFACL',
            'entries':lines,'sha256':hashlib.sha256('\n'.join(lines).encode()).hexdigest(),
            'acl_equivalence_verified':False,'effective_access_verified':False,
            'cutover_authorized':False,'author':'Abdelhalim Talbi'}

def compare(source,target):
    valid=source.get('status')=='POSIX_ACL_COLLECTED' and target.get('status')=='POSIX_ACL_COLLECTED'
    equal=valid and source['entries']==target['entries']
    return {'status':'POSIX_ACL_MATCH_UNVERIFIED' if equal else 'BLOCKED',
            'posix_acl_equal':bool(equal),'acl_equivalence_verified':False,
            'effective_access_verified':False,'cutover_authorized':False}
