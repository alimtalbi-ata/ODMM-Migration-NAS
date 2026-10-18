"""Explicit LDAPS collection -> validated snapshot -> atomic RBAC/quarantine.

No cutover authorization. Transport provenance is not independently attested.
"""
import re
from ldap_tls_client import collect_ldaps_snapshot
from directory_snapshot_adapter import normalize_directory_export
from human_approval_registry import ApprovalError

class LDAPSImportError(ApprovalError): pass

def import_ldaps_directory(ledger, *, endpoint, base_dn, version, bind_dn,
                           password, ca_file, now, expected_previous_digest=None,
                           timeout=10, page_size=200, max_pages=100, ldap_module=None,
                           collector=collect_ldaps_snapshot):
    """Read and fully validate before beginning atomic SQLite sync/quarantine.

    `collector` injection supports deterministic tests; only a real trusted
    transport and operator controls can establish real-world provenance.
    """
    if type(now) is not int or now < 0:
        raise LDAPSImportError('INVALID_TIME')
    if expected_previous_digest is not None and (not isinstance(expected_previous_digest,str)
        or not re.fullmatch(r'[0-9a-f]{64}', expected_previous_digest)):
        raise LDAPSImportError('INVALID_EXPECTED_DIGEST')
    snapshot = collector(endpoint=endpoint, base_dn=base_dn, version=version,
                         bind_dn=bind_dn, password=password, ca_file=ca_file,
                         timeout=timeout, page_size=page_size, max_pages=max_pages,
                         ldap_module=ldap_module)
    if not isinstance(snapshot,dict) or snapshot.get('transport') != 'LDAPS_TLS_CA_VALIDATED_BY_CLIENT' \
       or snapshot.get('authenticated') is not False or snapshot.get('cutover_authorized') is not False:
        raise LDAPSImportError('UNTRUSTED_TRANSPORT_RESULT')
    normalized=snapshot.get('normalized')
    if not isinstance(normalized,dict) or normalized.get('source') != 'LDAP_EXPORT':
        raise LDAPSImportError('INVALID_SNAPSHOT_SOURCE')
    # The normalized snapshot has a different shape from the raw directory
    # export. Reconstruct the strict export and verify its original digest.
    accounts=[]
    for item in normalized.get('accounts',[]):
        if not isinstance(item,dict) or set(item) != {'reviewer','role','active'}:
            raise LDAPSImportError('INVALID_SNAPSHOT_ACCOUNT')
        role=item['role']
        if role not in (None,'security','operations') or type(item['active']) is not bool:
            raise LDAPSImportError('INVALID_SNAPSHOT_ROLE')
        groups={'security':['ODMM_SECURITY_REVIEWERS'],
                'operations':['ODMM_OPERATIONS_REVIEWERS'],None:[]}[role]
        # A disabled reviewer with a role is representable; active reviewer
        # without a role is not. Disabled role-less entries are also valid.
        if item['active'] and role is None:
            raise LDAPSImportError('INVALID_ACTIVE_REVIEWER')
        accounts.append({'id':item['reviewer'],'enabled':item['active'],'groups':groups})
    export={'source':'LDAP_EXPORT','version':normalized.get('version'),'accounts':accounts}
    checked=normalize_directory_export(export)
    if checked['normalized'] != normalized or checked['sha256'] != snapshot.get('sha256'):
        raise LDAPSImportError('SNAPSHOT_DIGEST_MISMATCH')
    outcome=ledger.synchronize_and_quarantine(export,
        expected_previous_digest=expected_previous_digest,now=now)
    return {**outcome,'status':'LDAPS_SNAPSHOT_ATOMICALLY_APPLIED',
            'transport':'LDAPS_TLS_CA_VALIDATED_BY_CLIENT',
            'directory_authenticated':False,'cutover_authorized':False,
            'production_qualified':False}
