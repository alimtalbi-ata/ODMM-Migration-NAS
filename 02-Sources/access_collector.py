"""V177.6 conservative, read-only local POSIX evidence collection.
Never impersonates a user, probes write/delete, or claims NFSv4/SMB qualification.
"""
import os, stat, hashlib, json
from pathlib import Path

def collect_local(path, *, expected_root=None):
    p=Path(path)
    if expected_root is not None:
        root=Path(expected_root).resolve(strict=True)
        candidate=p.absolute()
        if not candidate.is_relative_to(root):
            raise ValueError("path outside collection root")
    st=os.lstat(p)
    if stat.S_ISLNK(st.st_mode):
        return {'status':'BLOCKED_SYMLINK','path':str(p)}
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return {'status':'UNSUPPORTED_FILE_TYPE','path':str(p)}
    evidence={'status':'OBSERVED_LOCAL_ONLY','path':str(p),'type':'directory' if stat.S_ISDIR(st.st_mode) else 'file','uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'size':st.st_size,'xattrs':{},'limitations':['NOT_EFFECTIVE_ACCESS','NOT_NFSV4_ACL','NOT_SMB_DACL','NOT_IDENTITY_IMPERSONATION']}
    if hasattr(os,'listxattr'):
        try:
            for key in sorted(os.listxattr(p,follow_symlinks=False)):
                try: evidence['xattrs'][key]=hashlib.sha256(os.getxattr(p,key,follow_symlinks=False)).hexdigest()
                except OSError: evidence.setdefault('unreadable_xattrs',[]).append(key)
        except OSError as exc: evidence['xattrs_error']=type(exc).__name__
    evidence['evidence_sha256']=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return evidence

def capability_report(protocol):
    if protocol not in ('LOCAL_POSIX','NFSv3','NFSv4','SMB'):
        raise ValueError('unsupported protocol')
    return {'protocol':protocol,'metadata_observation':'LOCAL_ONLY' if protocol=='LOCAL_POSIX' else 'UNQUALIFIED','effective_access':'UNQUALIFIED','acl_fidelity':'UNQUALIFIED','safe_for_cutover':False}
