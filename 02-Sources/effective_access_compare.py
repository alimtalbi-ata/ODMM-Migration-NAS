"""Offline comparison of explicit source/target access observations; never grants access."""
import hashlib
import json
from vendor_qualification import PROTOCOLS

ACTIONS = ('read', 'write', 'delete', 'traverse', 'acl_read', 'acl_write')
DECISIONS = ('ALLOW', 'DENY', 'UNKNOWN')
class AccessComparisonError(ValueError): pass

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()

def _validate(observations):
    if not isinstance(observations, list) or not observations:
        raise AccessComparisonError('EMPTY_OBSERVATIONS')
    results = {}
    for o in observations:
        if not isinstance(o, dict) or set(o) != {'principal_alias', 'object_alias', 'action', 'decision'}:
            raise AccessComparisonError('INVALID_OBSERVATION')
        p, obj, action, decision = (o[k] for k in ('principal_alias','object_alias','action','decision'))
        if not all(isinstance(v, str) and v and len(v) <= 128 and not any(c in v for c in '/\\\r\n\x00') for v in (p,obj)):
            raise AccessComparisonError('INVALID_ALIAS')
        if action not in ACTIONS or decision not in DECISIONS:
            raise AccessComparisonError('INVALID_ACTION_OR_DECISION')
        key = (p, obj, action)
        if key in results:
            raise AccessComparisonError('DUPLICATE_OBSERVATION')
        results[key] = decision
    return results

def compare_effective_access(protocol, source, target):
    if protocol not in PROTOCOLS:
        raise AccessComparisonError('UNSUPPORTED_PROTOCOL')
    left, right = _validate(source), _validate(target)
    findings = []
    for key in sorted(left.keys() | right.keys()):
        a, b = left.get(key, 'MISSING'), right.get(key, 'MISSING')
        status = 'MATCH' if a == b and a in ('ALLOW','DENY') else ('MISMATCH' if a in ('ALLOW','DENY') and b in ('ALLOW','DENY') else 'INDETERMINATE')
        findings.append({'principal_alias':key[0], 'object_alias':key[1], 'action':key[2], 'source':a, 'target':b, 'status':status})
    summary = {status: sum(x['status'] == status for x in findings) for status in ('MATCH','MISMATCH','INDETERMINATE')}
    report = {'schema':'odmm.effective-access-compare.v1', 'protocol':protocol, 'findings':findings,
              'summary':summary, 'equivalent_observations':summary['MISMATCH']==0 and summary['INDETERMINATE']==0,
              'live_access_test_performed':False, 'identity_mapping_verified':False,
              'production_qualified':False, 'manual_review_required':True,
              'limitations':['OFFLINE_OPERATOR_SUPPLIED_OBSERVATIONS','NO_LIVE_NAS_ACCESS','SHA256_NOT_AUTHENTICATION']}
    return {'report':report, 'sha256':hashlib.sha256(canonical(report)).hexdigest()}

def verify_comparison(bundle):
    if not isinstance(bundle, dict) or set(bundle) != {'report','sha256'} or not isinstance(bundle['report'],dict):
        raise AccessComparisonError('INVALID_BUNDLE')
    report=bundle['report']
    if report.get('schema')!='odmm.effective-access-compare.v1' or any(report.get(k) is not False for k in ('live_access_test_performed','identity_mapping_verified','production_qualified')) or report.get('manual_review_required') is not True:
        raise AccessComparisonError('UNSAFE_REPORT')
    try: digest=hashlib.sha256(canonical(report)).hexdigest()
    except (ValueError, TypeError, OverflowError) as exc: raise AccessComparisonError('NONCANONICAL_REPORT') from exc
    if digest != bundle['sha256']: raise AccessComparisonError('HASH_MISMATCH')
    return True
