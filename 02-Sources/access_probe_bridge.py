"""Conservatively convert a local read-only probe into a single comparison observation."""
import hashlib
import json
from effective_access_compare import canonical

class ProbeBridgeError(ValueError): pass

def observation_from_probe(bundle, principal_alias, object_alias):
    if not isinstance(bundle,dict) or set(bundle)!={'report','sha256'} or not isinstance(bundle['report'],dict):
        raise ProbeBridgeError('INVALID_BUNDLE')
    report=bundle['report']
    try: digest=hashlib.sha256(canonical(report)).hexdigest()
    except (ValueError,TypeError,OverflowError) as exc: raise ProbeBridgeError('INVALID_REPORT') from exc
    if digest!=bundle['sha256']: raise ProbeBridgeError('HASH_MISMATCH')
    required={'schema':'odmm.readonly-access-probe.v1','action':'open_readonly',
              'identity_impersonation':False,'file_content_read':False,'write_performed':False,
              'remote_nas_identity_verified':False,'effective_acl_equivalence_verified':False,
              'production_qualified':False}
    if any(report.get(k)!=v or type(report.get(k)) is not type(v) for k,v in required.items()):
        raise ProbeBridgeError('UNSAFE_REPORT')
    if not isinstance(report.get('execution_euid'),int) or isinstance(report['execution_euid'],bool) or report['execution_euid']<0:
        raise ProbeBridgeError('INVALID_IDENTITY')
    if not isinstance(report.get('execution_egid'),int) or isinstance(report['execution_egid'],bool) or report['execution_egid']<0:
        raise ProbeBridgeError('INVALID_IDENTITY')
    outcome=report.get('outcome')
    if outcome not in ('OPEN_READ_SUCCEEDED','OPEN_READ_DENIED'):
        raise ProbeBridgeError('INVALID_OUTCOME')
    for alias in (principal_alias,object_alias):
        if not isinstance(alias,str) or not alias or len(alias)>128 or any(c in alias for c in '/\\\r\n\x00'):
            raise ProbeBridgeError('INVALID_ALIAS')
    observation={'principal_alias':principal_alias,'object_alias':object_alias,'action':'read',
                 'decision':'ALLOW' if outcome=='OPEN_READ_SUCCEEDED' else 'DENY'}
    return {'observation':observation,'evidence_sha256':digest,
            'scope':'LOCAL_OPEN_ONLY','identity_mapping_verified':False,
            'nas_acl_equivalence_verified':False,'production_qualified':False}

def compare_probe_pairs(protocol, source, target):
    """Compare two already captured probe bundles, never perform an access operation."""
    from effective_access_compare import compare_effective_access
    if not isinstance(source,list) or not isinstance(target,list) or not source or not target:
        raise ProbeBridgeError('EMPTY_PROBES')
    left=[observation_from_probe(x['bundle'],x['principal_alias'],x['object_alias']) for x in source]
    right=[observation_from_probe(x['bundle'],x['principal_alias'],x['object_alias']) for x in target]
    comparison=compare_effective_access(protocol,[x['observation'] for x in left],[x['observation'] for x in right])
    return {'comparison':comparison,'source_evidence_sha256':[x['evidence_sha256'] for x in left],
            'target_evidence_sha256':[x['evidence_sha256'] for x in right],
            'limitations':['LOCAL_OPEN_ONLY','NO_AD_LDAP_IDENTITY_MAPPING','NO_NAS_ACL_EQUIVALENCE','UNAUTHENTICATED_EVIDENCE'],
            'production_qualified':False}
