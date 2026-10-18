"""ODMM V202.6: compare independently collected, read-only effective-access evidence.
Author: Abdelhalim Talbi. No impersonation, network requests, or writes.
"""
import hashlib
import json
import re

SCHEMA = 'odmm.effective.access.v2026'
ACTIONS = frozenset(('READ_DATA', 'LIST_DIRECTORY', 'READ_ATTRIBUTES', 'READ_ACL'))
DECISIONS = frozenset(('ALLOW', 'DENY'))
PRINCIPAL = re.compile(r'^(SID:S-1-[0-9-]+|UID:[0-9]+|GID:[0-9]+|TEST:[A-Za-z0-9_.@-]{1,128})$')

def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def _path(p):
    return isinstance(p, str) and bool(p) and len(p) <= 2048 and '\x00' not in p and '\\' not in p and not p.startswith('/') and all(x not in ('', '.', '..') for x in p.split('/'))

def _record(record):
    if not isinstance(record, dict) or set(record) != {'path', 'principal', 'action', 'decision', 'method', 'evidence_id'}:
        return False
    return (_path(record['path']) and isinstance(record['principal'], str) and bool(PRINCIPAL.fullmatch(record['principal']))
            and record['action'] in ACTIONS and record['decision'] in DECISIONS
            and record['method'] == 'INDEPENDENT_READ_ONLY_PROBE'
            and isinstance(record['evidence_id'], str) and 8 <= len(record['evidence_id']) <= 256)

def compare(source, target, *, principal_mapping, source_attested=False, target_attested=False,
            max_records=100000):
    """Records are externally supplied. Attestation flags are caller assertions, NOT verified signatures.

    Unattested or absent records never become MATCH. No WRITE/DELETE probes are permitted.
    """
    if type(max_records) is not int or not 1 <= max_records <= 1000000:
        raise ValueError('INVALID_LIMIT')
    if not isinstance(source, list) or not isinstance(target, list) or len(source) + len(target) > max_records:
        raise ValueError('INVALID_OR_EXCESSIVE_RECORDS')
    if not isinstance(principal_mapping, dict) or any(not isinstance(a, str) or not isinstance(b, str) or not PRINCIPAL.fullmatch(a) or not PRINCIPAL.fullmatch(b) for a,b in principal_mapping.items()):
        raise ValueError('INVALID_MAPPING')
    if any(not _record(r) for r in source + target):
        raise ValueError('INVALID_OR_UNSAFE_PROBE')
    def index(records, source_side):
        out = {}
        duplicates = set()
        for r in records:
            principal = principal_mapping.get(r['principal']) if source_side else r['principal']
            key = (r['path'], principal if principal is not None else 'UNMAPPED:'+r['principal'], r['action'])
            if key in out:
                duplicates.add(key)
            out[key] = r
        return out, duplicates
    a, ad = index(source, True)
    b, bd = index(target, False)
    rows = []
    counts = {'MATCH': 0, 'MISMATCH': 0, 'UNVERIFIED': 0}
    for key in sorted(set(a) | set(b)):
        left, right = a.get(key), b.get(key)
        if key in ad or key in bd:
            state, reason = 'UNVERIFIED', 'DUPLICATE_EVIDENCE'
        elif key[1].startswith('UNMAPPED:'):
            state, reason = 'UNVERIFIED', 'UNMAPPED_PRINCIPAL'
        elif left is None or right is None:
            state, reason = 'UNVERIFIED', 'MISSING_SIDE_EVIDENCE'
        elif source_attested is not True or target_attested is not True:
            state, reason = 'UNVERIFIED', 'UNATTESTED_EVIDENCE'
        elif left['decision'] != right['decision']:
            state, reason = 'MISMATCH', 'EFFECTIVE_PERMISSION_DIFFERENCE'
        else:
            state, reason = 'MATCH', 'OBSERVED_READ_ONLY_DECISIONS_EQUAL'
        counts[state] += 1
        rows.append({'path': key[0], 'target_principal': key[1], 'action': key[2], 'status': state,
                     'reason': reason, 'source_decision': left['decision'] if left else None,
                     'target_decision': right['decision'] if right else None,
                     'source_evidence_id': left['evidence_id'] if left else None,
                     'target_evidence_id': right['evidence_id'] if right else None})
    status = 'MISMATCH' if counts['MISMATCH'] else 'UNVERIFIED' if counts['UNVERIFIED'] or not rows else 'MATCH'
    report = {'schema': SCHEMA, 'author': 'Abdelhalim Talbi', 'status': status, 'counts': counts,
              'checks': rows, 'source_attested_declared': source_attested is True,
              'target_attested_declared': target_attested is True,
              'attestation_cryptographically_verified': False, 'cutover_authorized': False,
              'writes_to_nas': False, 'native_engine_default': True, 'silent_fallback_allowed': False,
              'limitations': ['EXTERNAL_EVIDENCE_NOT_COLLECTED_BY_THIS_MODULE',
                              'CALLER_ATTESTATION_NOT_CRYPTOGRAPHIC', 'READ_ONLY_ACTIONS_ONLY',
                              'NO_LIVE_AD_LDAP_IMPERSONATION', 'NO_VENDOR_CERTIFICATION']}
    report['report_sha256'] = _hash(report)
    return report

def verify(report):
    if not isinstance(report, dict):
        return False
    try:
        return (report.get('schema') == SCHEMA and report.get('cutover_authorized') is False
                and report.get('writes_to_nas') is False and report.get('native_engine_default') is True
                and report.get('silent_fallback_allowed') is False
                and report.get('attestation_cryptographically_verified') is False
                and report.get('status') in ('MATCH', 'MISMATCH', 'UNVERIFIED')
                and report.get('report_sha256') == _hash({k:v for k,v in report.items() if k != 'report_sha256'}))
    except (TypeError, ValueError):
        return False
