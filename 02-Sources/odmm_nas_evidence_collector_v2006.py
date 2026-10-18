"""Fail-closed read-only mounted NAS evidence collector. Author: Abdelhalim Talbi.
POSIX observations are NOT a proof of SMB/NFS ACL equivalence.
"""
import hashlib
import os
import stat
from pathlib import Path

class CollectionError(RuntimeError): pass

def collect(root, *, max_entries=100000, max_bytes=1<<40):
    if type(max_entries) is not int or not 1 <= max_entries <= 1000000: raise CollectionError('INVALID_ENTRY_LIMIT')
    if type(max_bytes) is not int or max_bytes < 0: raise CollectionError('INVALID_BYTE_LIMIT')
    root=Path(root)
    if root.is_symlink() or not root.is_dir(): raise CollectionError('INVALID_ROOT')
    base=root.resolve(strict=True)
    entries={}; total=0
    for directory, dirs, files in os.walk(base,topdown=True,followlinks=False):
        dirs.sort(); files.sort()
        for name in dirs+files:
            p=Path(directory)/name
            rel=p.relative_to(base).as_posix()
            if rel in entries: raise CollectionError('DUPLICATE_PATH')
            if len(entries)>=max_entries: raise CollectionError('ENTRY_LIMIT_EXCEEDED')
            try:
                before=p.lstat()
                kind='symlink' if stat.S_ISLNK(before.st_mode) else 'directory' if stat.S_ISDIR(before.st_mode) else 'file' if stat.S_ISREG(before.st_mode) else 'special'
                if kind=='symlink' and name in dirs: dirs.remove(name)
                item={'kind':kind,'size':before.st_size,'owner':before.st_uid,'group':before.st_gid,
                      'mode':stat.S_IMODE(before.st_mode),'mtime_ns':before.st_mtime_ns,
                      'xattrs':None,'sha256':None,'acl_status':'NOT_COLLECTED','access_status':'NOT_TESTED'}
                if hasattr(os,'listxattr'):
                    try:
                        names=os.listxattr(p,follow_symlinks=False)
                        item['xattrs']={n:hashlib.sha256(os.getxattr(p,n,follow_symlinks=False)).hexdigest() for n in sorted(names)}
                    except (OSError,NotImplementedError): pass
                if kind=='file':
                    total+=before.st_size
                    if total>max_bytes: raise CollectionError('BYTE_LIMIT_EXCEEDED')
                    digest=hashlib.sha256()
                    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
                    fd=os.open(p,flags)
                    try:
                        opened=os.fstat(fd)
                        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino): raise CollectionError('FILE_CHANGED_DURING_COLLECTION')
                        with os.fdopen(fd,'rb',closefd=False) as f:
                            while True:
                                chunk=f.read(1024*1024)
                                if not chunk: break
                                digest.update(chunk)
                        after=os.fstat(fd)
                        if (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(before.st_size,before.st_mtime_ns,before.st_ctime_ns): raise CollectionError('FILE_CHANGED_DURING_COLLECTION')
                        item['sha256']=digest.hexdigest()
                    finally: os.close(fd)
                entries[rel]=item
            except CollectionError: raise
            except (OSError,ValueError) as exc: raise CollectionError('COLLECTION_IO_FAILURE:'+rel) from exc
    return {'schema':'odmm.nas.readonly.inventory.v2006','author':'Abdelhalim Talbi','root':str(base),
            'entries':entries,'entry_count':len(entries),'file_bytes':total,'acl_fidelity_verified':False,
            'effective_access_verified':False,'cutover_authorized':False,'writes_performed':False}

def compare(source,target):
    if source.get('schema')!='odmm.nas.readonly.inventory.v2006' or target.get('schema')!='odmm.nas.readonly.inventory.v2006': raise CollectionError('INVALID_INVENTORY')
    left=source['entries'];right=target['entries']; differences=[]
    for path in sorted(set(left)|set(right)):
        if path not in left: differences.append({'path':path,'issue':'SOURCE_MISSING'});continue
        if path not in right: differences.append({'path':path,'issue':'TARGET_MISSING'});continue
        for key in ('kind','size','sha256','owner','group','mode','mtime_ns','xattrs'):
            if left[path][key] is None or right[path][key] is None:
                differences.append({'path':path,'issue':'UNVERIFIED_'+key.upper()})
            elif left[path][key]!=right[path][key]: differences.append({'path':path,'issue':'MISMATCH_'+key.upper()})
    return {'schema':'odmm.nas.pair.report.v2006','author':'Abdelhalim Talbi','source_entries':len(left),
            'target_entries':len(right),'differences':differences,'difference_count':len(differences),
            'status':'BLOCKED' if differences else 'POSIX_EVIDENCE_MATCHES_ACL_UNVERIFIED',
            'acl_fidelity_verified':False,'effective_access_verified':False,'cutover_authorized':False,
            'native_engine_default':True,'writes_performed':False}
