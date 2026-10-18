"""ODMM V204.2 read-only extended fidelity qualification; fail closed on unsupported metadata.
Auteur : Abdelhalim Talbi. No NAS writes or cutover authorization.
"""
from __future__ import annotations
import hashlib, os, stat
from pathlib import Path

FIELDS = ('content', 'mode', 'uid', 'gid', 'mtime_ns', 'xattrs', 'hardlinks', 'sparse', 'nfs4_acl', 'smb_acl', 'smb_ads')

def _hash(p):
    h=hashlib.sha256()
    fd=os.open(p, os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): raise ValueError('NOT_REGULAR')
        while True:
            b=os.read(fd, 1024*1024)
            if not b: break
            h.update(b)
        after=os.fstat(fd)
        if (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino): raise ValueError('CHANGED_DURING_READ')
        return h.hexdigest()
    finally: os.close(fd)

def _xattrs(p):
    if not hasattr(os,'listxattr') or not hasattr(os,'getxattr'): return None
    try:
        names=os.listxattr(p,follow_symlinks=False)
        return {n:hashlib.sha256(os.getxattr(p,n,follow_symlinks=False)).hexdigest() for n in sorted(names)}
    except (OSError,NotImplementedError): return None

def _walk(root):
    root=Path(root).resolve(strict=True)
    if not root.is_dir(): raise ValueError('NOT_DIRECTORY')
    entries={}; groups={}
    for base,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            p=Path(base)/name; rel=p.relative_to(root).as_posix(); st=p.lstat()
            if stat.S_ISLNK(st.st_mode): kind='symlink'
            elif stat.S_ISREG(st.st_mode): kind='file'
            elif stat.S_ISDIR(st.st_mode): kind='directory'
            else: kind='unsupported'
            item={'kind':kind,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'mtime_ns':st.st_mtime_ns}
            if kind=='file':
                item['content']=_hash(p); item['xattrs']=_xattrs(p)
                item['sparse']=(st.st_blocks*512<st.st_size) if hasattr(st,'st_blocks') else None
                groups.setdefault((st.st_dev,st.st_ino),[]).append(rel)
            elif kind=='symlink': item['link_target']=os.readlink(p)
            entries[rel]=item
        dirs[:]=[d for d in dirs if not (Path(base)/d).is_symlink()]
    for paths in groups.values():
        for rel in paths: entries[rel]['hardlinks']=sorted(paths)
    return entries

def compare_trees(source,target,*,required=('content','mode','uid','gid','mtime_ns','xattrs','hardlinks'),max_entries=100000):
    """Read-only qualification. NFSv4/SMB ACL and ADS never inferred from POSIX metadata."""
    required=tuple(required)
    if not required or any(k not in FIELDS for k in required): raise ValueError('UNKNOWN_REQUIREMENT')
    src=_walk(source); dst=_walk(target)
    if len(src)>max_entries or len(dst)>max_entries: raise ValueError('ENTRY_LIMIT')
    findings=[]; mismatches=0; unverified=0
    for rel in sorted(set(src)|set(dst)):
        a=src.get(rel); b=dst.get(rel)
        if a is None or b is None:
            findings.append({'path':rel,'field':'presence','status':'MISMATCH'}); mismatches+=1; continue
        if a['kind']!=b['kind'] or a['kind']=='unsupported':
            findings.append({'path':rel,'field':'kind','status':'MISMATCH'}); mismatches+=1; continue
        if a['kind']=='symlink' and a['link_target']!=b['link_target']:
            findings.append({'path':rel,'field':'link_target','status':'MISMATCH'}); mismatches+=1
        for field in required:
            if field in ('nfs4_acl','smb_acl','smb_ads'):
                status='UNVERIFIED'
            elif field in ('content','xattrs','hardlinks','sparse') and a['kind']!='file':
                continue
            elif a.get(field) is None or b.get(field) is None:
                status='UNVERIFIED'
            else: status='MATCH' if a.get(field)==b.get(field) else 'MISMATCH'
            if status!='MATCH':
                findings.append({'path':rel,'field':field,'status':status})
                mismatches+=status=='MISMATCH'; unverified+=status=='UNVERIFIED'
    status='MISMATCH' if mismatches else 'UNVERIFIED' if unverified else 'MATCH'
    return {'schema':'odmm.extended_fidelity.v2042','author':'Abdelhalim Talbi','status':status,'source_entries':len(src),'target_entries':len(dst),'mismatches':mismatches,'unverified':unverified,'findings':findings,'writes_to_nas':False,'cutover_authorized':False,'acl_fidelity_verified':False}
