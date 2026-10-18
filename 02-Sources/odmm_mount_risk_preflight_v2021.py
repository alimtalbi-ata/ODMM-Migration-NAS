"""ODMM V202.1: evidence-aware mount risk assessment. Author: Abdelhalim Talbi.
Read-only; observations never certify preservation or authorize cutover.
"""
import hashlib, json
from odmm_live_readonly_preflight_v2020 import inspect_pair, verify as verify_live
from odmm_unified_preflight_v2019 import evaluate, verify as verify_unified, KNOWN
SCHEMA='odmm.mount.risk.preflight.v2021'
NETWORK={'nfs':'NFS','nfs4':'NFS','cifs':'SMB','smb3':'SMB','fuse.sshfs':'OTHER_NETWORK'}
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def classify(observation):
    mount=observation.get('mount',{})
    fs=mount.get('filesystem_type') if mount.get('status')=='OBSERVED' else None
    protocol=NETWORK.get(str(fs).lower(),'LOCAL_OR_OTHER' if fs else 'UNKNOWN')
    return {'protocol':protocol,'filesystem_type':fs,'mount_status':mount.get('status','UNKNOWN'),
            'xattr_listing':observation.get('xattr',{}).get('status','UNKNOWN'),
            'acl_fidelity':'UNVERIFIED','ads_fidelity':'UNVERIFIED','identity_fidelity':'UNVERIFIED'}
def assess(source,target,*,required,source_capabilities=None,target_capabilities=None,evidence=None,strategy='NATIVE'):
    if not isinstance(required,(list,tuple)) or not required or any(not isinstance(x,str) or x not in KNOWN for x in required):
        raise ValueError('INVALID_REQUIRED_DOMAINS')
    live=inspect_pair(source,target)
    if not verify_live(live): raise ValueError('INVALID_LIVE_REPORT')
    a=classify(live['source']); b=classify(live['target'])
    # Observations do NOT auto-promote declared capabilities to SUPPORTED.
    unified=evaluate(source_capabilities or {},target_capabilities or {},required=required,evidence=evidence,strategy=strategy)
    if not verify_unified(unified): raise ValueError('INVALID_UNIFIED_REPORT')
    risks=[]
    for side,obs in [('source',a),('target',b)]:
        if obs['protocol']=='UNKNOWN': risks.append({'side':side,'risk':'MOUNT_PROTOCOL_UNKNOWN','severity':'BLOCKER'})
        if obs['xattr_listing']!='OBSERVED' and 'xattrs' in required: risks.append({'side':side,'risk':'XATTR_LIST_UNAVAILABLE','severity':'BLOCKER'})
        if obs['protocol']=='SMB' and 'ads' in required: risks.append({'side':side,'risk':'ADS_CONTENT_NOT_ATTESTED','severity':'BLOCKER'})
        if obs['protocol']=='NFS' and 'nfs4_acl' in required: risks.append({'side':side,'risk':'NFS4_ACL_NOT_ATTESTED','severity':'BLOCKER'})
    for domain in unified['domains']:
        risks.append({'side':'pair','domain':domain['feature'],'risk':'INDEPENDENT_FIDELITY_NOT_PROVEN','severity':'BLOCKER'})
    result={'schema':SCHEMA,'source':a,'target':b,'required_domains':list(required),'risks':risks,
            'live_report_sha256':live['report_sha256'],'unified_report_sha256':unified['report_sha256'],
            'status':'BLOCKED_PENDING_INDEPENDENT_LIVE_QUALIFICATION','cutover_authorized':False,
            'writes_to_nas':False,'native_engine_default':strategy=='NATIVE','silent_fallback_allowed':False,
            'limitations':['MOUNT_CLASSIFICATION_IS_OBSERVATIONAL','NO_REAL_NAS_FIDELITY_ATTESTATION','NO_VENDOR_CERTIFICATION']}
    result['report_sha256']=digest(result)
    return result
def verify(report):
    return isinstance(report,dict) and report.get('schema')==SCHEMA and report.get('cutover_authorized') is False and report.get('writes_to_nas') is False and report.get('silent_fallback_allowed') is False and isinstance(report.get('risks'),list) and digest({k:v for k,v in report.items() if k!='report_sha256'})==report.get('report_sha256')
