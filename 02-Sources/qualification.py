"""V177.1: read-only legacy consistency checks and portable metadata inventory."""
import os, stat, sqlite3, hashlib, json
from pathlib import Path

def inspect_legacy(db_path):
    """Read-only diagnosis; never mutate legacy records."""
    con=sqlite3.connect(f'file:{Path(db_path).resolve()}?mode=ro',uri=True)
    con.row_factory=sqlite3.Row
    try:
        tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required={'recovery_approvals','recovery_executions'}
        if not required.issubset(tables):
            return {'status':'SCHEMA_INCOMPLETE','missing':sorted(required-tables),'orphans':[]}
        rows=con.execute("""SELECT a.approval_id,a.intent_id,a.state FROM recovery_approvals a
           LEFT JOIN recovery_executions e ON a.approval_id=e.approval_id
           WHERE a.state='CONSUMED' AND e.execution_id IS NULL ORDER BY a.approval_id""").fetchall()
        return {'status':'RECONCILIATION_REQUIRED' if rows else 'CONSISTENT',
                'orphans':[dict(r) for r in rows], 'automatic_repair':False}
    finally: con.close()

def metadata_inventory(path):
    """No symlink following; inventory only, not ACL preservation."""
    p=Path(path); st=os.lstat(p)
    result={'path':str(p),'kind':'symlink' if stat.S_ISLNK(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'other',
            'mode':stat.S_IMODE(st.st_mode),'size':st.st_size,'mtime_ns':st.st_mtime_ns,
            'uid':getattr(st,'st_uid',None),'gid':getattr(st,'st_gid',None),
            'xattrs_supported':hasattr(os,'listxattr'),'xattrs':[], 'acl_verified':False}
    if hasattr(os,'listxattr'):
        try:
            for name in sorted(os.listxattr(p,follow_symlinks=False)):
                value=os.getxattr(p,name,follow_symlinks=False)
                result['xattrs'].append({'name':name,'sha256':hashlib.sha256(value).hexdigest(),'size':len(value)})
        except (OSError,NotImplementedError,TypeError) as exc:
            result['xattr_error']=type(exc).__name__
    return result
