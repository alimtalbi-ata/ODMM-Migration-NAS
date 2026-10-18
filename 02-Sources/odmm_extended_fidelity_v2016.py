"""ODMM V201.6: read-only extended metadata comparison. Author: Abdelhalim Talbi.
No implicit fallback; unsupported features are UNVERIFIED, not PASS.
"""
import hashlib, json, os, stat
from pathlib import Path
SCHEMA='odmm.extended.fidelity.v2016'
def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def inventory(root, *, max_entries=100000):
    root=Path(root).resolve(strict=True)
    if not root.is_dir(): raise ValueError('ROOT_NOT_DIRECTORY')
    records={}; hardlinks={}; stack=[(root,'')]
    while stack:
        directory,relative=stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                rel=f'{relative}/{entry.name}'.lstrip('/')
                if len(records)>=max_entries: raise ValueError('ENTRY_LIMIT')
                st=entry.stat(follow_symlinks=False)
                kind='symlink' if stat.S_ISLNK(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'special'
                rec={'kind':kind,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'size':st.st_size,'mtime_ns':st.st_mtime_ns}
                if kind=='symlink':rec['link_target']=os.readlink(entry.path)
                if kind=='file' and st.st_nlink>1:hardlinks.setdefault((st.st_dev,st.st_ino),[]).append(rel)
                try:
                    names=os.listxattr(entry.path,follow_symlinks=False)
                    rec['xattrs']={n:hashlib.sha256(os.getxattr(entry.path,n,follow_symlinks=False)).hexdigest() for n in sorted(names)}
                    rec['xattrs_status']='OBSERVED'
                except (OSError,NotImplementedError):
                    rec['xattrs']={};rec['xattrs_status']='UNVERIFIED'
                if kind=='file':
                    rec['allocated_bytes']=st.st_blocks*512 if hasattr(st,'st_blocks') else None
                    rec['sparse_status']='UNVERIFIED' # st_blocks is only an allocation hint, not hole-map equivalence
                records[rel]=rec
                if kind=='directory':stack.append((Path(entry.path),rel))
    groups=sorted([sorted(v) for v in hardlinks.values() if len(v)>1])
    return {'records':records,'hardlink_groups':groups,'ads_status':'UNVERIFIED','acl_status':'UNVERIFIED'}
def compare(source,target,*,max_entries=100000):
    a=inventory(source,max_entries=max_entries);b=inventory(target,max_entries=max_entries)
    differences=[];unverified=[]
    for p in sorted(set(a['records'])|set(b['records'])):
        x=a['records'].get(p);y=b['records'].get(p)
        if x is None or y is None:differences.append({'path':p,'field':'presence'});continue
        for k in ('kind','mode','uid','gid','size','mtime_ns','link_target'):
            if x.get(k)!=y.get(k):differences.append({'path':p,'field':k})
        if x['xattrs_status']=='OBSERVED' and y['xattrs_status']=='OBSERVED':
            if x['xattrs']!=y['xattrs']:differences.append({'path':p,'field':'xattrs'})
        else:unverified.append({'path':p,'field':'xattrs'})
        if x['kind']=='file':unverified.append({'path':p,'field':'sparse_hole_map'})
    if a['hardlink_groups']!=b['hardlink_groups']:differences.append({'field':'hardlink_topology'})
    unverified.extend([{'field':'smb_ads'},{'field':'protocol_acl'},{'field':'effective_access'}])
    report={'schema':SCHEMA,'author':'Abdelhalim Talbi','differences':differences,'unverified':unverified,
      'status':'MISMATCH' if differences else 'BLOCKED_UNVERIFIED','cutover_authorized':False,
      'native_engine_default':True,'writes_to_nas':False}
    report['report_sha256']=digest(report)
    return report
def verify(report):
    return isinstance(report,dict) and report.get('schema')==SCHEMA and report.get('cutover_authorized') is False and report.get('report_sha256')==digest({k:v for k,v in report.items() if k!='report_sha256'})
