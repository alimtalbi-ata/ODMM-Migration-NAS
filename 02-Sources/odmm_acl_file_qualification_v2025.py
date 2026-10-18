"""ODMM V202.5: read-only, fail-closed per-file ACL evidence qualification.
Author: Abdelhalim Talbi. Never infers effective access from ACL syntax.
"""
import hashlib
import json
from pathlib import PurePosixPath
from identity_acl import IdentityMap
from odmm_acl_canonical_v2009 import compare_collected

SCHEMA = 'odmm.acl.file.qualification.v2025'

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()

def _valid_path(path):
    return (isinstance(path, str) and bool(path) and '\\' not in path and '\x00' not in path
            and not path.startswith('/') and all(x not in ('', '.', '..') for x in path.split('/'))
            and str(PurePosixPath(path)) == path)

def qualify(source, target, source_identities, target_identities, mapping, *, identity_verified=False,
            max_files=10000, max_aces_per_file=10000):
    """Compare provided collected ACL evidence, not live effective rights.

    Evidence shape: {relative/path: {status:'COLLECTED_UNVERIFIED',protocol:'NFSV4'|'SMB',entries:[...]}}.
    Unknown/missing/malformed evidence is UNVERIFIED, not a false MATCH.
    """
    if not isinstance(mapping, IdentityMap):
        raise ValueError('INVALID_IDENTITY_MAPPING')
    if type(max_files) is not int or not 1 <= max_files <= 100000 or type(max_aces_per_file) is not int or not 1 <= max_aces_per_file <= 100000:
        raise ValueError('INVALID_LIMITS')
    if not isinstance(source, dict) or not isinstance(target, dict):
        raise ValueError('INVALID_EVIDENCE')
    paths = sorted(set(source) | set(target))
    if len(paths) > max_files or any(not _valid_path(p) for p in paths):
        raise ValueError('INVALID_OR_EXCESSIVE_PATHS')
    results = []
    counts = {'MATCH': 0, 'MISMATCH': 0, 'UNVERIFIED': 0}
    for path in paths:
        a, b = source.get(path), target.get(path)
        state, reason, details = 'UNVERIFIED', 'MISSING_ACL_EVIDENCE', None
        if isinstance(a, dict) and isinstance(b, dict):
            ae, be = a.get('entries'), b.get('entries')
            if not isinstance(ae, list) or not isinstance(be, list) or len(ae) > max_aces_per_file or len(be) > max_aces_per_file:
                reason = 'INVALID_OR_EXCESSIVE_ACES'
            elif a.get('protocol') not in ('NFSV4', 'SMB') or b.get('protocol') not in ('NFSV4', 'SMB'):
                reason = 'UNSUPPORTED_PROTOCOL'
            else:
                details = compare_collected(a, b, source_identities, target_identities, mapping, identity_verified=identity_verified)
                if details.get('status') == 'CANONICAL_MATCH_UNVERIFIED':
                    state, reason = 'MATCH', 'CANONICAL_ACL_EQUAL_ONLY'
                elif details.get('reason') or 'IDENTITY_NOT_VERIFIED' in details.get('differences', []):
                    reason = 'UNVERIFIED_OR_UNMAPPED_ACL'
                elif details.get('missing_mappings'):
                    reason = 'UNMAPPED_IDENTITY'
                elif 'ACL_ORDER_OR_CONTENT_MISMATCH' in details.get('differences', []):
                    state, reason = 'MISMATCH', 'ACL_ORDER_OR_CONTENT_MISMATCH'
                else:
                    reason = 'INSUFFICIENT_EVIDENCE'
        counts[state] += 1
        results.append({'path': path, 'status': state, 'reason': reason,
                        'source_protocol': a.get('protocol') if isinstance(a, dict) else None,
                        'target_protocol': b.get('protocol') if isinstance(b, dict) else None,
                        'canonical_evidence_sha256': details.get('evidence_sha256') if isinstance(details, dict) else None,
                        'effective_access_verified': False})
    overall = 'MISMATCH' if counts['MISMATCH'] else 'UNVERIFIED' if counts['UNVERIFIED'] or not paths else 'MATCH'
    report = {'schema': SCHEMA, 'author': 'Abdelhalim Talbi', 'status': overall,
              'counts': counts, 'files': results, 'identity_mapping_declared_verified': identity_verified is True,
              'effective_access_verified': False, 'cutover_authorized': False,
              'writes_to_nas': False, 'native_engine_default': True, 'silent_fallback_allowed': False,
              'limitations': ['CANONICAL_EQUIVALENCE_NOT_EFFECTIVE_ACCESS', 'NO_LIVE_AD_LDAP_AUTHORIZATION_TEST', 'NO_VENDOR_CERTIFICATION']}
    report['report_sha256'] = _digest(report)
    return report

def verify(report):
    if not isinstance(report, dict):
        return False
    try:
        return (report.get('schema') == SCHEMA and report.get('cutover_authorized') is False
                and report.get('effective_access_verified') is False and report.get('writes_to_nas') is False
                and report.get('native_engine_default') is True and report.get('silent_fallback_allowed') is False
                and report.get('status') in ('MATCH', 'MISMATCH', 'UNVERIFIED')
                and report.get('report_sha256') == _digest({k: v for k, v in report.items() if k != 'report_sha256'}))
    except (TypeError, ValueError):
        return False
