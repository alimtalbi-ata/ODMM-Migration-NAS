"""ODMM V202.4 per-file read-only evidence. Author: Abdelhalim Talbi.
Observed file equivalence is NOT independent NAS migration certification.
"""
import hashlib, json, os, stat
from pathlib import Path
from odmm_sparse_ads_preflight_v2017 import sparse_extents
from odmm_ads_fidelity_v2018 import hash_ads, compare_ads_evidence
SCHEMA='odmm.file.fidelity.v2024'
def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _sha(path,max_bytes):
    h=hashlib.sha256(); total=0
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    fd=os.open(path,flags)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): raise ValueError('NOT_REGULAR_FILE')
        if before.st_size>max_bytes: raise ValueError('FILE_BYTE_LIMIT')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            while True:
                data=stream.read(min(1024*1024,max_bytes-total+1))
                if not data: break
                total+=len(data)
                if total>max_bytes: raise ValueError('FILE_BYTE_LIMIT')
                h.update(data)
        after=os.fstat(fd)
        if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns) or total!=before.st_size:
            raise ValueError('FILE_CHANGED_DURING_READ')
        return h.hexdigest()
    finally: os.close(fd)
def _xattrs(path):
    try:
        names=os.listxattr(path,follow_symlinks=False)
        return {'status':'OBSERVED','values':{n:hashlib.sha256(os.getxattr(path,n,follow_symlinks=False)).hexdigest() for n in sorted(names)}}
    except (OSError,NotImplementedError,AttributeError):
        return {'status':'UNVERIFIED','values':{}}
def _inventory(root,max_entries,max_file_bytes):
    root=Path(root)
    if root.is_symlink() or not root.is_dir(): raise ValueError('INVALID_ROOT')
    root=root.resolve(strict=True)
    result={}; stack=[(root,'')]
    while stack:
        folder,prefix=stack.pop()
        with os.scandir(folder) as iterator:
            for entry in iterator:
                if len(result)>=max_entries: raise ValueError('ENTRY_LIMIT')
                rel=(prefix+'/'+entry.name).lstrip('/')
                s=entry.stat(follow_symlinks=False)
                kind='file' if stat.S_ISREG(s.st_mode) else 'dir' if stat.S_ISDIR(s.st_mode) else 'symlink' if stat.S_ISLNK(s.st_mode) else 'special'
                r={'kind':kind,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtime_ns':s.st_mtime_ns,'size':s.st_size,'xattrs':_xattrs(entry.path)}
                if kind=='file':
                    r['sha256']=_sha(entry.path,max_file_bytes)
                    try:r['sparse']=sparse_extents(entry.path,max_extents=10000)
                    except (OSError,ValueError):r['sparse']={'status':'UNVERIFIED'}
                    r['ads']=hash_ads(entry.path)
                    r['hardlink_identity']=(s.st_dev,s.st_ino) if s.st_nlink>1 else None
                elif kind=='symlink':r['link_target']=os.readlink(entry.path)
                elif kind=='dir':stack.append((Path(entry.path),rel))
                result[rel]=r
    groups={}
    for name,record in result.items():
        ident=record.pop('hardlink_identity',None)
        if ident is not None:groups.setdefault(ident,[]).append(name)
    return result,sorted(sorted(v) for v in groups.values() if len(v)>1)
def compare(source,target,*,max_entries=10000,max_file_bytes=1<<30,max_findings=10000):
    if any(type(v)!=int or v<1 for v in (max_entries,max_file_bytes,max_findings)):raise ValueError('INVALID_LIMIT')
    a=Path(source); b=Path(target)
    if a.is_symlink() or b.is_symlink():raise ValueError('SYMLINK_ROOT')
    a=a.resolve(strict=True);b=b.resolve(strict=True)
    if a==b or a in b.parents or b in a.parents:raise ValueError('OVERLAPPING_ROOTS')
    sa,ga=_inventory(a,max_entries,max_file_bytes);sb,gb=_inventory(b,max_entries,max_file_bytes)
    findings=[];counts={'MATCH':0,'MISMATCH':0,'UNVERIFIED':0}
    def record(path,field,status):
        counts[status]+=1
        if status!='MATCH':
            if len(findings)>=max_findings:raise ValueError('FINDING_LIMIT')
            findings.append({'path':path,'field':field,'status':status})
    for name in sorted(set(sa)|set(sb)):
        x=sa.get(name);y=sb.get(name)
        if x is None or y is None:record(name,'presence','MISMATCH');continue
        for field in ('kind','mode','uid','gid','mtime_ns','size','sha256','link_target'):
            if field in x or field in y:record(name,field,'MATCH' if x.get(field)==y.get(field) else 'MISMATCH')
        xx=x['xattrs'];yy=y['xattrs']
        record(name,'xattrs','UNVERIFIED' if xx['status']!='OBSERVED' or yy['status']!='OBSERVED' else 'MATCH' if xx['values']==yy['values'] else 'MISMATCH')
        if x['kind']=='file' and y['kind']=='file':
            xs=x['sparse'];ys=y['sparse']
            record(name,'sparse','UNVERIFIED' if xs.get('status')!='OBSERVED' or ys.get('status')!='OBSERVED' else 'MATCH' if xs['size']==ys['size'] and xs['extents']==ys['extents'] else 'MISMATCH')
            record(name,'ads',compare_ads_evidence(x['ads'],y['ads'])['status'])
    record('','hardlink_topology','MATCH' if ga==gb else 'MISMATCH')
    # No NFSv4/SMB ACL or effective-access evidence is synthesized from POSIX mode.
    record('','protocol_acl','UNVERIFIED');record('','effective_access','UNVERIFIED')
    status='MISMATCH' if counts['MISMATCH'] else 'UNVERIFIED' if counts['UNVERIFIED'] else 'MATCH'
    report={'schema':SCHEMA,'author':'Abdelhalim Talbi','status':status,'counts':counts,'findings':findings,
            'source_files':len(sa),'target_files':len(sb),'cutover_authorized':False,
            'writes_to_nas':False,'native_engine_default':True,'silent_fallback_allowed':False,
            'limitations':['NOT_POINT_IN_TIME_CONSISTENT','PROTOCOL_ACL_UNVERIFIED','EFFECTIVE_ACCESS_UNVERIFIED','WINDOWS_ADS_UNVERIFIED_UNLESS_NATIVE_OBSERVATION','NO_VENDOR_CERTIFICATION']}
    report['report_sha256']=digest(report)
    return report
def verify(report):
    return isinstance(report,dict) and report.get('schema')==SCHEMA and report.get('cutover_authorized') is False and report.get('writes_to_nas') is False and report.get('native_engine_default') is True and report.get('silent_fallback_allowed') is False and report.get('status') in ('MATCH','MISMATCH','UNVERIFIED') and report.get('report_sha256')==digest({k:v for k,v in report.items() if k!='report_sha256'})
