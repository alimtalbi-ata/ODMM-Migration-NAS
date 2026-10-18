"""Conservative local read-only access observation; no user impersonation or NAS qualification."""
import os, stat, hashlib, json
from path_preflight import preflight_path, PathPreflightError

class AccessProbeError(ValueError): pass

def probe_readonly(root, relative_path, *, expected_euid, expected_egid=None):
    if not isinstance(expected_euid,int) or isinstance(expected_euid,bool) or expected_euid < 0 or os.geteuid()!=expected_euid:
        raise AccessProbeError('EXECUTION_IDENTITY_MISMATCH')
    if expected_egid is not None and (not isinstance(expected_egid,int) or isinstance(expected_egid,bool) or os.getegid()!=expected_egid):
        raise AccessProbeError('EXECUTION_GROUP_MISMATCH')
    try: before=preflight_path(root,relative_path)
    except (PathPreflightError,OSError) as exc: raise AccessProbeError('PATH_NOT_QUALIFIED') from exc
    if not stat.S_ISREG(before['mode']): raise AccessProbeError('NOT_REGULAR_FILE')
    flags=os.O_RDONLY|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    rootfd=None; fd=None
    try:
        rootfd=os.open(root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
        parts=str(relative_path).split('/')
        if any(x in ('','.','..') for x in parts): raise AccessProbeError('UNSAFE_PATH')
        parent=rootfd
        for part in parts[:-1]:
            nxt=os.open(part,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0),dir_fd=parent)
            if parent!=rootfd: os.close(parent)
            parent=nxt
        try: fd=os.open(parts[-1],flags,dir_fd=parent)
        finally:
            if parent!=rootfd: os.close(parent)
        st=os.fstat(fd)
        if (st.st_dev,st.st_ino,st.st_mode)!=(before['device'],before['inode'],before['mode']) or not stat.S_ISREG(st.st_mode):
            raise AccessProbeError('FILE_CHANGED')
        # Opening for reading checks permissions of the current execution identity, not ACL equivalence.
        outcome='OPEN_READ_SUCCEEDED'
    except PermissionError:
        outcome='OPEN_READ_DENIED'
    except AccessProbeError: raise
    except OSError as exc: raise AccessProbeError('PROBE_OS_ERROR') from exc
    finally:
        if fd is not None: os.close(fd)
        if rootfd is not None: os.close(rootfd)
    report={'schema':'odmm.readonly-access-probe.v1','outcome':outcome,'action':'open_readonly',
            'execution_euid':expected_euid,'execution_egid':os.getegid(),
            'identity_impersonation':False,'file_content_read':False,'write_performed':False,
            'remote_nas_identity_verified':False,'effective_acl_equivalence_verified':False,
            'production_qualified':False,
            'limitations':['LOCAL_PROCESS_IDENTITY_ONLY','OPEN_SUCCESS_NOT_NFS_SMB_ACL_EQUIVALENCE','NO_REMOTE_SERVER_ATTESTATION','NO_FILE_CONTENT_READ']}
    encoded=json.dumps(report,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    return {'report':report,'sha256':hashlib.sha256(encoded).hexdigest()}
