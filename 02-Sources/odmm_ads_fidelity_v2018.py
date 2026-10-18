"""ODMM V201.8: conservative ADS hash comparison and capability requirements.
Author: Abdelhalim Talbi. No NAS writes or cutover authorization.
"""
import hashlib, json, os, re
from pathlib import Path
from odmm_sparse_ads_preflight_v2017 import ads_inventory, sparse_extents

SCHEMA='odmm.ads.fidelity.v2018'
_STREAM=re.compile(r'^:[^:/\\]+:\$DATA$',re.I)

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def hash_ads(path, *, max_stream_bytes=1024*1024*1024, chunk_size=1024*1024):
    """Read named streams on Windows only; fail closed on partial/error/size mismatch."""
    if os.name!='nt':
        return {'status':'UNSUPPORTED_PLATFORM','streams':[]}
    p=Path(path)
    if p.is_symlink() or not p.is_file():
        return {'status':'INVALID_FILE','streams':[]}
    inv=ads_inventory(p)
    if inv.get('status')!='OBSERVED_NAMES_AND_SIZES_ONLY':
        return {'status':'UNVERIFIED_INVENTORY','streams':[]}
    out=[]
    seen=set()
    for stream in inv['streams']:
        name=stream.get('name')
        size=stream.get('size')
        if name=='::$DATA':
            continue # default stream is covered by main-file SHA-256
        if not isinstance(name,str) or not _STREAM.fullmatch(name) or name in seen or not isinstance(size,int) or size<0:
            return {'status':'INVALID_STREAM','streams':[]}
        seen.add(name)
        if size>max_stream_bytes:
            return {'status':'LIMIT_EXCEEDED','streams':[]}
        h=hashlib.sha256(); read=0
        try:
            with open(str(p)+name,'rb',buffering=0) as f:
                while True:
                    data=f.read(min(chunk_size,max_stream_bytes-read+1))
                    if not data: break
                    read+=len(data)
                    if read>max_stream_bytes: return {'status':'LIMIT_EXCEEDED','streams':[]}
                    h.update(data)
        except (OSError,ValueError):
            return {'status':'READ_FAILED','streams':[]}
        if read!=size:
            return {'status':'SIZE_CHANGED_DURING_READ','streams':[]}
        out.append({'name':name,'size':size,'sha256':h.hexdigest()})
    return {'status':'OBSERVED','streams':sorted(out,key=lambda s:s['name'])}

def compare_ads_evidence(source,target):
    """Compare observed ADS hashes; empty streams valid only if both inventories succeeded."""
    def valid(v):
        return isinstance(v,dict) and v.get('status')=='OBSERVED' and isinstance(v.get('streams'),list) and all(
            isinstance(x,dict) and isinstance(x.get('name'),str) and _STREAM.fullmatch(x['name']) and
            isinstance(x.get('size'),int) and x['size']>=0 and isinstance(x.get('sha256'),str) and
            bool(re.fullmatch('[0-9a-f]{64}',x['sha256'])) for x in v['streams']) and len({x['name'] for x in v['streams']})==len(v['streams'])
    if not valid(source) or not valid(target): status='UNVERIFIED'
    else: status='MATCH' if sorted(source['streams'],key=lambda x:x['name'])==sorted(target['streams'],key=lambda x:x['name']) else 'MISMATCH'
    report={'schema':SCHEMA,'status':status,'source':source,'target':target,'cutover_authorized':False,'writes_to_nas':False,'native_engine_default':True}
    report['report_sha256']=digest(report)
    return report

def capability_matrix(source,target,*,required=('content','metadata','acl','effective_access','sparse','ads')):
    """Explicit capability evidence: UNKNOWN never becomes SUPPORTED."""
    valid={'SUPPORTED','UNSUPPORTED','UNKNOWN'}
    if not isinstance(source,dict) or not isinstance(target,dict) or not isinstance(required,(list,tuple)) or not required or len(set(required))!=len(required):
        raise ValueError('INVALID_CAPABILITY_INPUT')
    rows=[]
    for feature in required:
        if not isinstance(feature,str) or not feature:
            raise ValueError('INVALID_FEATURE')
        a=source.get(feature,'UNKNOWN'); b=target.get(feature,'UNKNOWN')
        if a not in valid or b not in valid:
            raise ValueError('INVALID_CAPABILITY_STATUS')
        rows.append({'feature':feature,'source':a,'target':b,'status':'POSSIBLE' if a==b=='SUPPORTED' else 'BLOCKED'})
    result={'schema':'odmm.capability.matrix.v2018','features':rows,'status':'BLOCKED_PENDING_LIVE_ATTESTATION','cutover_authorized':False,'silent_fallback_allowed':False,'native_engine_default':True}
    result['report_sha256']=digest(result)
    return result

def extend_fidelity_report(base, *, ads_report=None, sparse_report=None, capability_report=None):
    """Add v2018 domains without modifying/weakening V201.1 report."""
    from odmm_migration_fidelity_report_v2011 import verify_report_digest
    if not verify_report_digest(base):
        raise ValueError('INVALID_BASE_REPORT_DIGEST')
    inputs={'ads':(ads_report,SCHEMA,'MATCH'),'sparse':(sparse_report,'odmm.sparse.ads.preflight.v2017','MATCH'),
            'capabilities':(capability_report,'odmm.capability.matrix.v2018',None)}
    domains={}
    for name,(report,schema,match) in inputs.items():
        if not isinstance(report,dict) or report.get('schema')!=schema or digest({k:v for k,v in report.items() if k!='report_sha256'})!=report.get('report_sha256'):
            domains[name]={'status':'UNVERIFIED','issue':'MISSING_OR_INVALID_EVIDENCE'}
        elif match is not None and report.get('status')!=match:
            domains[name]={'status':'BLOCKED','issue':'NOT_MATCHED'}
        elif name=='capabilities' and (not isinstance(report.get('features'),list) or not report['features'] or any(x.get('status')!='POSSIBLE' for x in report['features'])):
            domains[name]={'status':'BLOCKED','issue':'UNSUPPORTED_OR_UNKNOWN_CAPABILITY'}
        else:
            domains[name]={'status':'OBSERVED_NOT_INDEPENDENTLY_ATTESTED','issue':'LIVE_QUALIFICATION_REQUIRED'}
    result={'schema':'odmm.extended.fidelity.v2018','base_report_sha256':base['report_sha256'],'domains':domains,
            'status':'BLOCKED_PENDING_INDEPENDENT_QUALIFICATION','cutover_authorized':False,'native_engine_default':True,'writes_to_nas':False}
    result['report_sha256']=digest(result)
    return result
