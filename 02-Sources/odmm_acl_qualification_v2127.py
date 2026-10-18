"""Read-only, fail-closed ACL/identity qualification. Author: Abdelhalim Talbi.

No real vendor ACL translation, AD/LDAP interrogation, effective access probing or cutover.
"""
from collections.abc import Mapping
from dataclasses import dataclass

VENDORS = frozenset(('netapp', 'flashblade', 'onefs'))
PROTOCOLS = frozenset(('NFS4', 'SMB3'))
RIGHTS = frozenset(('READ', 'WRITE', 'EXECUTE', 'DELETE', 'READ_ACL', 'WRITE_ACL', 'CHANGE_OWNER'))

@dataclass(frozen=True)
class ACLAssessment:
    direction: str
    status: str
    blockers: tuple[str, ...]
    discrepancies: tuple[str, ...]
    checked_principals: int
    cutover_authorized: bool = False
    acl_fidelity_verified: bool = False
    engine: str = 'ODMM_NATIVE'

def _entries(endpoint, side, blockers):
    if not isinstance(endpoint, Mapping):
        blockers.append(side + '_EVIDENCE_INVALID'); return {}
    entries = endpoint.get('acl_entries')
    if not isinstance(entries, (tuple, list)) or not entries:
        blockers.append(side + '_ACL_EVIDENCE_MISSING'); return {}
    out = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            blockers.append(side + '_ACL_ENTRY_INVALID'); continue
        principal = entry.get('principal')
        effect = entry.get('effect')
        rights = entry.get('rights')
        inherited = entry.get('inherited')
        if (not isinstance(principal, str) or not principal.strip() or
            effect not in ('ALLOW', 'DENY') or type(inherited) is not bool or
            not isinstance(rights, (tuple, list, set, frozenset)) or
            not rights or any(not isinstance(r, str) or r not in RIGHTS for r in rights)):
            blockers.append(side + '_ACL_ENTRY_INVALID'); continue
        key = (principal, effect, inherited, tuple(sorted(set(rights))))
        if key in out:
            blockers.append(side + '_DUPLICATE_ACL_ENTRY')
        out[key] = True
    return out

def qualify_acl_pair(source, target, *, effective_access=None, identity_mapping=None):
    """Compare *supplied* snapshots; never infer actual access or permit migration.

    effective_access must be independent probe results: {principal: {source: {right: bool},
    target: {right: bool}}}. These are still untrusted until validated externally.
    """
    if not isinstance(source, Mapping) or not isinstance(target, Mapping):
        raise ValueError('ENDPOINTS_REQUIRED')
    sv, tv = source.get('vendor'), target.get('vendor')
    direction = f'{sv}_TO_{tv}'
    blockers, discrepancies = [], []
    if sv not in VENDORS or tv not in VENDORS or sv == tv:
        blockers.append('UNSUPPORTED_DIRECTION')
    sp, tp = source.get('protocol'), target.get('protocol')
    if sp not in PROTOCOLS or tp not in PROTOCOLS:
        blockers.append('PROTOCOL_UNVERIFIED')
    elif sp != tp:
        blockers.append('CROSS_PROTOCOL_TRANSLATION_UNQUALIFIED')
    for side, ep in (('SOURCE', source), ('TARGET', target)):
        if ep.get('acl_model') not in ('NFS4', 'NTFS'):
            blockers.append(side + '_ACL_MODEL_UNVERIFIED')
        if not isinstance(ep.get('identity_domain'), str) or not ep['identity_domain'].strip():
            blockers.append(side + '_IDENTITY_DOMAIN_UNVERIFIED')
        if ep.get('snapshot_complete') is not True:
            blockers.append(side + '_SNAPSHOT_INCOMPLETE')
    src = _entries(source, 'SOURCE', blockers)
    tgt = _entries(target, 'TARGET', blockers)
    if source.get('acl_model') != target.get('acl_model'):
        blockers.append('ACL_MODEL_TRANSLATION_UNQUALIFIED')
    if source.get('identity_domain') != target.get('identity_domain'):
        blockers.append('IDENTITY_DOMAIN_MAPPING_REQUIRED')
    if src != tgt:
        discrepancies.extend('MISSING_TARGET_ACE:' + repr(k) for k in sorted(src.keys() - tgt.keys()))
        discrepancies.extend('EXTRA_TARGET_ACE:' + repr(k) for k in sorted(tgt.keys() - src.keys()))
    if not isinstance(identity_mapping, Mapping) or not identity_mapping:
        blockers.append('IDENTITY_MAPPING_EVIDENCE_MISSING')
    else:
        principals = {k[0] for k in src}
        if any(not isinstance(k, str) or not isinstance(v, str) or not v.strip() for k, v in identity_mapping.items()):
            blockers.append('IDENTITY_MAPPING_INVALID')
        if not principals.issubset(identity_mapping.keys()):
            blockers.append('IDENTITY_MAPPING_INCOMPLETE')
        if len(set(identity_mapping.values())) != len(identity_mapping):
            blockers.append('IDENTITY_MAPPING_COLLISION')
    checked = 0
    if not isinstance(effective_access, Mapping) or not effective_access:
        blockers.append('EFFECTIVE_ACCESS_EVIDENCE_MISSING')
    else:
        for principal in sorted({k[0] for k in src} | {k[0] for k in tgt}):
            probe = effective_access.get(principal)
            if not isinstance(probe, Mapping) or not isinstance(probe.get('source'), Mapping) or not isinstance(probe.get('target'), Mapping):
                blockers.append('EFFECTIVE_ACCESS_INCOMPLETE:' + principal); continue
            a, b = probe['source'], probe['target']
            if set(a) != RIGHTS or set(b) != RIGHTS or any(type(v) is not bool for v in list(a.values()) + list(b.values())):
                blockers.append('EFFECTIVE_ACCESS_INCOMPLETE:' + principal); continue
            checked += 1
            for right in sorted(RIGHTS):
                if a[right] != b[right]:
                    discrepancies.append('EFFECTIVE_ACCESS_MISMATCH:' + principal + ':' + right)
    blockers.extend(('VENDOR_ACL_API_NOT_QUALIFIED', 'INDEPENDENT_PROBE_ATTESTATION_REQUIRED',
                     'DISTRIBUTED_FENCING_NOT_VERIFIED', 'CUTOVER_NOT_AUTHORIZED'))
    return ACLAssessment(direction, 'BLOCKED', tuple(sorted(set(blockers))),
                         tuple(sorted(set(discrepancies))), checked)
