"""ODMM V202.0 read-only mount observation. Author: Abdelhalim Talbi.
No write probes, no capability certification, no cutover authorization.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

SCHEMA = 'odmm.live.readonly.preflight.v2020'

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def _mount_details(path):
    if os.name != 'posix' or not Path('/proc/self/mountinfo').is_file():
        return {'status':'UNKNOWN', 'reason':'MOUNTINFO_UNAVAILABLE'}
    matches=[]
    for line in Path('/proc/self/mountinfo').read_text(errors='replace').splitlines():
        left, sep, right = line.partition(' - ')
        if not sep: continue
        cols=left.split(); rest=right.split()
        if len(cols)<5 or len(rest)<2: continue
        mount=cols[4].replace('\\040',' ')
        if path == mount or path.startswith(mount.rstrip('/')+'/'):
            matches.append((len(mount), mount, rest[0], cols[5].split(',')))
    if not matches: return {'status':'UNKNOWN','reason':'MOUNT_NOT_FOUND'}
    _, mount, fstype, options=max(matches)
    return {'status':'OBSERVED','mount_point':mount,'filesystem_type':fstype,
            'mount_readonly_declared':'ro' in options}

def observe(root):
    """Observe existing directory without creating or modifying files.
    Refuses symlink root and non-directory root; no recursive traversal.
    """
    p=Path(root)
    if p.is_symlink(): raise ValueError('SYMLINK_ROOT_REFUSED')
    if not p.is_dir(): raise ValueError('ROOT_NOT_DIRECTORY')
    real=str(p.resolve(strict=True))
    s=os.stat(real,follow_symlinks=False)
    if not stat.S_ISDIR(s.st_mode): raise ValueError('ROOT_NOT_DIRECTORY')
    mount=_mount_details(real)
    try:
        os.listxattr(real,follow_symlinks=False)
        xattr={'status':'OBSERVED','operation':'LIST_ONLY','preservation':'UNVERIFIED'}
    except (OSError,AttributeError) as exc:
        xattr={'status':'UNKNOWN','reason':type(exc).__name__,'preservation':'UNVERIFIED'}
    try:
        v=os.statvfs(real)
        filesystem={'status':'OBSERVED','block_size':v.f_frsize,'total_blocks':v.f_blocks}
    except OSError as exc:
        filesystem={'status':'UNKNOWN','reason':type(exc).__name__}
    return {'path':real,'mount':mount,'filesystem':filesystem,'xattr':xattr,
            'acl_nfs4':'UNVERIFIED','acl_smb':'UNVERIFIED','ads':'UNVERIFIED',
            'sparse_preservation':'UNVERIFIED','hardlink_preservation':'UNVERIFIED',
            'effective_access':'UNVERIFIED','writes_performed':False}

def inspect_pair(source,target):
    a=Path(source).resolve(strict=True); b=Path(target).resolve(strict=True)
    if a==b or a in b.parents or b in a.parents:
        raise ValueError('OVERLAPPING_ROOTS_REFUSED')
    result={'schema':SCHEMA,'source':observe(source),'target':observe(target),
            'status':'BLOCKED_PENDING_INDEPENDENT_FIDELITY_TESTS',
            'cutover_authorized':False,'writes_to_nas':False,
            'native_engine_default':True,'silent_fallback_allowed':False,
            'limitations':['READ_ONLY_OBSERVATIONS_ARE_NOT_WRITE_CAPABILITY_PROOFS',
                           'NO_ACL_OR_ADS_FIDELITY_ATTESTATION','NO_VENDOR_CERTIFICATION']}
    result['report_sha256']=digest(result)
    return result

def verify(report):
    return isinstance(report,dict) and report.get('schema')==SCHEMA and report.get('cutover_authorized') is False and report.get('writes_to_nas') is False and isinstance(report.get('report_sha256'),str) and digest({k:v for k,v in report.items() if k!='report_sha256'})==report['report_sha256']
