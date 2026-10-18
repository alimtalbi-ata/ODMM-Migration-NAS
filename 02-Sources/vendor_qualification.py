"""Vendor-neutral, offline NAS qualification plans. No vendor support is asserted."""
import hashlib
import json

VENDORS = ('NetApp', 'Dell', 'Pure', 'IBM', 'HPE', 'Hitachi')
PROTOCOLS = ('NFSv4', 'SMB')
CHECKS = ('mount_identity', 'acl_capture', 'identity_mapping', 'effective_access', 'crash_recovery', 'audit_integrity')

def plan(vendor, protocol, endpoint_alias, evidence=None):
    if vendor not in VENDORS or protocol not in PROTOCOLS:
        raise ValueError('UNSUPPORTED_TEST_PROFILE')
    if not isinstance(endpoint_alias,str) or not endpoint_alias.strip() or any(x in endpoint_alias for x in ('/', '\\', '\n')):
        raise ValueError('INVALID_ENDPOINT_ALIAS')
    evidence = {} if evidence is None else evidence
    if not isinstance(evidence,dict) or set(evidence)-set(CHECKS):
        raise ValueError('INVALID_EVIDENCE')
    checks=[]
    for check in CHECKS:
        item=evidence.get(check)
        valid=isinstance(item,dict) and item.get('status')=='PASS' and isinstance(item.get('sha256'),str) and len(item['sha256'])==64 and all(c in '0123456789abcdef' for c in item['sha256'])
        checks.append({'check':check,'status':'EVIDENCE_SUBMITTED' if valid else 'NOT_QUALIFIED'})
    payload={'schema':'odmm.vendor-qualification.v1','vendor':vendor,'protocol':protocol,'endpoint_alias':endpoint_alias,'checks':checks,'production_qualified':False,'manual_review_required':True}
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'report':payload,'sha256':digest}

def matrix():
    return [plan(v,p,'UNASSIGNED') for v in VENDORS for p in PROTOCOLS]
