"""ODMM V201.9 unified, fail-closed migration preflight. Author: Abdelhalim Talbi.

This module evaluates *provided evidence*, not live vendor certification.
"""
import hashlib
import json
import re
from odmm_ads_fidelity_v2018 import capability_matrix

SCHEMA = 'odmm.unified.preflight.v2019'
KNOWN = frozenset(('content','metadata','acl','effective_access','sparse','ads','xattrs','hardlinks','symlinks','owners','timestamps','nfs4_acl','smb_acl','identity_mapping'))
HEX64 = re.compile(r'^[0-9a-f]{64}$')

def _digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def verify(report):
    return isinstance(report,dict) and report.get('schema')==SCHEMA and isinstance(report.get('report_sha256'),str) and bool(HEX64.fullmatch(report['report_sha256'])) and _digest({k:v for k,v in report.items() if k!='report_sha256'})==report['report_sha256'] and report.get('cutover_authorized') is False

def evaluate(source, target, *, required, evidence=None, strategy='NATIVE'):
    """Assess explicit capabilities and independent evidence; never authorize cutover.

    Evidence per domain: {'status':'MATCH', 'source_sha256':..., 'target_sha256':...,
    'independently_attested': True}. Hashes are identifiers only, not proof of
    genuine attestation; external verification is still mandatory.
    """
    if not isinstance(required,(list,tuple)) or not required or len(set(map(str,required)))!=len(required) or any(not isinstance(x,str) or x not in KNOWN for x in required):
        raise ValueError('INVALID_REQUIRED_DOMAINS')
    if strategy not in ('NATIVE','EXPLICIT_EXTERNAL'):
        raise ValueError('INVALID_ENGINE_STRATEGY')
    if evidence is None: evidence={}
    if not isinstance(evidence,dict) or any(k not in KNOWN for k in evidence):
        raise ValueError('INVALID_EVIDENCE')
    matrix=capability_matrix(source,target,required=required)
    rows=[]
    for cap in matrix['features']:
        feature=cap['feature']; ev=evidence.get(feature)
        valid_ev=(isinstance(ev,dict) and ev.get('status')=='MATCH' and
                  ev.get('independently_attested') is True and
                  all(isinstance(ev.get(k),str) and HEX64.fullmatch(ev[k]) for k in ('source_sha256','target_sha256')))
        issues=[]
        if cap['source']!='SUPPORTED': issues.append('SOURCE_CAPABILITY_NOT_PROVEN')
        if cap['target']!='SUPPORTED': issues.append('TARGET_CAPABILITY_NOT_PROVEN')
        if not valid_ev: issues.append('INDEPENDENT_FIDELITY_EVIDENCE_MISSING')
        rows.append({'feature':feature,'source':cap['source'],'target':cap['target'],
                     'evidence_status':'DECLARED_MATCH_NOT_VERIFIED' if valid_ev else 'UNVERIFIED',
                     'status':'BLOCKED_PENDING_LIVE_VALIDATION' if not issues else 'BLOCKED',
                     'issues':issues})
    result={'schema':SCHEMA,'required_domains':list(required),'domains':rows,
            'status':'BLOCKED_PENDING_INDEPENDENT_LIVE_QUALIFICATION',
            'engine_strategy':strategy,'native_engine_default':strategy=='NATIVE',
            'explicit_external_selection_required':strategy=='EXPLICIT_EXTERNAL',
            'silent_fallback_allowed':False,'cutover_authorized':False,
            'writes_to_nas':False,'capability_matrix_sha256':matrix['report_sha256'],
            'limitations':['PROVIDED_CAPABILITIES_NOT_LIVE_PROBED','ATTESTATION_NOT_CRYPTOGRAPHICALLY_VERIFIED','NO_VENDOR_CERTIFICATION']}
    result['report_sha256']=_digest(result)
    return result
