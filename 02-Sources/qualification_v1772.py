"""V177.2: conservative, read-only qualification utilities."""
import hashlib, json, os, sqlite3, stat
from pathlib import Path
from qualification import metadata_inventory

def compare_metadata(source, target):
    """Compare inventories; ACLs are explicitly NOT certified."""
    a=metadata_inventory(source); b=metadata_inventory(target)
    fields=('kind','mode','size','uid','gid','mtime_ns')
    mismatches={k:{'source':a[k],'target':b[k]} for k in fields if a[k]!=b[k]}
    xa={x['name']:(x['sha256'],x['size']) for x in a['xattrs']}
    xb={x['name']:(x['sha256'],x['size']) for x in b['xattrs']}
    if xa!=xb: mismatches['xattrs']={'source':xa,'target':xb}
    unknown=bool(a.get('xattr_error') or b.get('xattr_error') or not a['xattrs_supported'] or not b['xattrs_supported'])
    return {'status':'MISMATCH' if mismatches else 'INDETERMINATE' if unknown else 'MATCH_METADATA_ONLY',
            'mismatches':mismatches,'acl_verified':False,'effective_access_verified':False,
            'xattr_incomplete':unknown}

def sqlite_health(db_path):
    """Read-only integrity check and WAL state; never checkpoint or repair."""
    p=Path(db_path).resolve()
    con=sqlite3.connect(f'file:{p}?mode=ro',uri=True,timeout=3)
    try:
        integrity=con.execute('PRAGMA integrity_check').fetchone()[0]
        foreign_keys=con.execute('PRAGMA foreign_key_check').fetchall()
        return {'integrity':integrity,'foreign_key_violations':len(foreign_keys),
                'status':'PASS' if integrity=='ok' and not foreign_keys else 'FAIL',
                'automatic_repair':False}
    finally: con.close()

def protocol_capability_report(path):
    """Report only observable local properties; never claim NAS semantics."""
    p=Path(path); st=os.lstat(p)
    return {'path':str(p),'is_symlink':stat.S_ISLNK(st.st_mode),
            'local_stat_available':True,'protocol':'UNDETERMINED',
            'nfs_durability_verified':False,'smb_durability_verified':False,
            'acl_fidelity_verified':False,'remote_atomic_rename_verified':False,
            'ready_for_remote_writes':False}
