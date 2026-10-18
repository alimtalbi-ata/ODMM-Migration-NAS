"""Offline, fail-closed inventory of potential ACL portability losses.

Vendor names label unverified test profiles, never imply support certification.
"""
from acl_portability_review import review_acl_portability, ACLPortabilityError
from acl_ace_compare import _hash

class ACLLossInventoryError(ValueError): pass
VENDORS = frozenset({'NetApp','Dell','Pure','IBM','HPE','Hitachi'})

def inventory_acl_losses(source_text, target_text, *, protocol, source_vendor, target_vendor):
    if source_vendor not in VENDORS or target_vendor not in VENDORS:
        raise ACLLossInventoryError('UNKNOWN_VENDOR_PROFILE')
    try:
        base = review_acl_portability(source_text,target_text,protocol=protocol)
    except ACLPortabilityError as exc:
        raise ACLLossInventoryError('INVALID_ACL_EVIDENCE') from exc
    r=base['report']; issues=[]
    src=r['source_inheritance']; tgt=r['target_inheritance']
    for i in r['drift_indices']:
        if i >= len(src):
            code='TARGET_EXTRA_ACE'
        elif i >= len(tgt):
            code='SOURCE_ACE_MISSING_ON_TARGET'
        else:
            a,b=src[i],tgt[i]
            if a['principal']!=b['principal']: code='PRINCIPAL_DRIFT'
            elif a['type']!=b['type']: code='ACE_TYPE_DRIFT'
            elif a['inheritance']!=b['inheritance']: code='INHERITANCE_DRIFT'
            else: code='ACE_OR_FLAGS_DRIFT'
        issues.append({'code':code,'ace_index':i,'severity':'BLOCKING'})
    for side,entries in [('source',src),('target',tgt)]:
        for e in entries:
            if e['opaque_flags']:
                issues.append({'code':'UNKNOWN_NATIVE_FLAGS','side':side,
                               'ace_index':e['index'],'severity':'UNVERIFIED'})
    if r['status']=='INDETERMINATE_PORTABILITY':
        issues.append({'code':'INCOMPLETE_PORTABILITY_EVIDENCE','severity':'UNVERIFIED'})
    if r['status']=='BLOCKED_ACL_PORTABILITY_DRIFT' and not r['drift_indices']:
        issues.append({'code':'ACL_METADATA_OR_PERMISSIONS_DRIFT','severity':'BLOCKING'})
    status=('BLOCKED_POTENTIAL_ACL_LOSS' if any(x['severity']=='BLOCKING' for x in issues)
            else 'INDETERMINATE_ACL_TRANSLATION' if issues
            else 'STRUCTURAL_MATCH_NOT_CERTIFIED')
    report={'schema':'odmm.acl-loss-inventory.v1','source_vendor':source_vendor,
            'target_vendor':target_vendor,'protocol':protocol,'status':status,
            'issues':issues,'portability_sha256':base['sha256'],
            'cutover_authorized':False,'production_qualified':False,
            'limitations':['OFFLINE_UNAUTHENTICATED_EVIDENCE','VENDOR_PROFILE_NOT_CERTIFICATION',
                           'NO_CROSS_PROTOCOL_TRANSLATION','NO_EFFECTIVE_ACCESS_PROOF']}
    return {'report':report,'sha256':_hash(report)}

def verify_acl_loss_inventory(bundle, source_text, target_text, *, protocol, source_vendor, target_vendor):
    expected=inventory_acl_losses(source_text,target_text,protocol=protocol,
                                   source_vendor=source_vendor,target_vendor=target_vendor)
    if bundle!=expected: raise ACLLossInventoryError('REPORT_MISMATCH')
    return True
