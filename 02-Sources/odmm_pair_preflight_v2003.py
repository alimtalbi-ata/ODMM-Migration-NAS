"""Read-only mounted NAS pair preflight; never grants cutover. Author: Abdelhalim Talbi."""
import os
import stat
from pathlib import Path
from odmm_storage_catalog_v2002 import assess_pair, REQUIRED_FIDELITY

class PreflightError(ValueError): pass

def _inspect(root, *, max_entries):
    path=Path(root)
    if not path.is_dir() or path.is_symlink(): raise PreflightError('INVALID_ROOT')
    counts={'directories':0,'files':0,'symlinks':0,'special':0,'entries':0}
    observed={'mode':False,'owner':False,'group':False,'mtime':False,'xattr':False}
    errors=[]
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in sorted(dirs+files):
            counts['entries']+=1
            if counts['entries']>max_entries: raise PreflightError('INVENTORY_LIMIT_EXCEEDED')
            p=Path(directory)/name
            try:
                s=p.lstat()
                if stat.S_ISLNK(s.st_mode): counts['symlinks']+=1
                elif stat.S_ISDIR(s.st_mode): counts['directories']+=1
                elif stat.S_ISREG(s.st_mode): counts['files']+=1
                else: counts['special']+=1
                observed.update(mode=True,owner=True,group=True,mtime=True)
                if hasattr(os,'listxattr'):
                    try: os.listxattr(p,follow_symlinks=False); observed['xattr']=True
                    except (OSError,NotImplementedError): pass
            except OSError as exc:
                errors.append({'path':str(p.relative_to(path)),'errno':exc.errno})
    return {'path':str(path.resolve()),'counts':counts,'observable':observed,'errors':errors}

def preflight(source_solution,target_solution,source_root,target_root,*,protocol,max_entries=100000):
    if protocol not in ('NFS','SMB','S3'): raise PreflightError('UNKNOWN_PROTOCOL')
    if type(max_entries) is not int or not 1<=max_entries<=1000000: raise PreflightError('INVALID_LIMIT')
    pair=assess_pair(source_solution,target_solution)
    if protocol not in pair['candidate_protocols']: raise PreflightError('PROTOCOL_NOT_SHARED')
    if protocol=='S3':
        return {'status':'S3_API_PREFLIGHT_REQUIRED','protocol':protocol,'pair':pair,
                'cutover_authorized':False,'reason':'MOUNTED_PATH_INSPECTION_CANNOT_VERIFY_OBJECT_VERSION_TAG_ACL'}
    source=_inspect(source_root,max_entries=max_entries)
    target=_inspect(target_root,max_entries=max_entries)
    checks={k:'UNVERIFIED' for k in REQUIRED_FIDELITY}
    for k in ('mode','owner','group','mtime','xattr'):
        if source['observable'][k] and target['observable'][k]: checks[k]='METADATA_READABLE_NOT_FIDELITY_PROVEN'
    if source['counts']['symlinks'] or source['counts']['special']:
        warnings=['NATIVE_TREE_ENGINE_REJECTS_NONREGULAR_ENTRIES']
    else: warnings=[]
    if source['errors'] or target['errors']: warnings.append('INVENTORY_IO_ERRORS')
    warnings.extend(['ACL_SEMANTICS_NOT_TESTED','EFFECTIVE_ACCESS_NOT_TESTED','SOURCE_TARGET_IDENTITY_MAPPING_NOT_TESTED'])
    return {'status':'READ_ONLY_PREFLIGHT','protocol':protocol,'pair':pair,'source':source,'target':target,
            'fidelity_checks':checks,'warnings':warnings,'native_engine_default':True,
            'external_fallback_requires_approval':True,'cutover_authorized':False,'acl_fidelity_verified':False}
