"""Offline fail-closed migration ACL risk aggregation; not cutover authorization."""
from acl_ace_compare import _hash
from acl_loss_inventory import inventory_acl_losses, ACLLossInventoryError

class MigrationACLRiskError(ValueError): pass

_RANK = {'STRUCTURAL_MATCH_NOT_CERTIFIED': 0,
         'INDETERMINATE_ACL_TRANSLATION': 1,
         'BLOCKED_POTENTIAL_ACL_LOSS': 2}

def assess_migration_acl_risk(migration_id, datasets):
    if not isinstance(migration_id, str) or not migration_id.strip() or len(migration_id) > 128:
        raise MigrationACLRiskError('INVALID_MIGRATION_ID')
    if not isinstance(datasets, list) or not datasets:
        raise MigrationACLRiskError('EMPTY_DATASETS')
    if len(datasets) > 10000:
        raise MigrationACLRiskError('DATASET_LIMIT')
    seen = set(); rows = []
    required = {'dataset_id', 'source_text', 'target_text', 'protocol', 'source_vendor', 'target_vendor'}
    for entry in datasets:
        if not isinstance(entry, dict) or set(entry) != required:
            raise MigrationACLRiskError('INVALID_DATASET')
        ident = entry['dataset_id']
        if not isinstance(ident, str) or not ident.strip() or len(ident) > 128 or ident in seen:
            raise MigrationACLRiskError('INVALID_OR_DUPLICATE_DATASET_ID')
        seen.add(ident)
        try:
            bundle = inventory_acl_losses(entry['source_text'], entry['target_text'],
                protocol=entry['protocol'], source_vendor=entry['source_vendor'], target_vendor=entry['target_vendor'])
        except (ACLLossInventoryError, TypeError, ValueError) as exc:
            raise MigrationACLRiskError('INVALID_DATASET_EVIDENCE') from exc
        r = bundle['report']
        rows.append({'dataset_id': ident, 'protocol': r['protocol'],
                     'source_vendor': r['source_vendor'], 'target_vendor': r['target_vendor'],
                     'status': r['status'], 'issue_codes': sorted(set(x['code'] for x in r['issues'])),
                     'issue_count': len(r['issues']), 'evidence_sha256': bundle['sha256']})
    rows.sort(key=lambda r:r['dataset_id'])
    counts = {k:sum(row['status']==k for row in rows) for k in _RANK}
    worst = max(rows, key=lambda row:_RANK[row['status']])['status']
    recommendations = []
    if counts['BLOCKED_POTENTIAL_ACL_LOSS']:
        recommendations.append('REVIEW_AND_REMEDIATE_ACL_DRIFT_BEFORE_CUTOVER')
    if counts['INDETERMINATE_ACL_TRANSLATION']:
        recommendations.append('COLLECT_COMPLETE_NATIVE_ACL_EVIDENCE')
    recommendations.extend(['VALIDATE_AD_LDAP_IDENTITIES_AND_EFFECTIVE_ACCESS',
                            'PERFORM_LIVE_NAS_VENDOR_QUALIFICATION', 'REQUIRE_HUMAN_CUTOVER_APPROVAL'])
    report = {'schema':'odmm.migration-acl-risk.v1', 'migration_id': migration_id,
              'overall_status': worst, 'dataset_count': len(rows), 'status_counts': counts,
              'datasets': rows, 'recommendations': recommendations,
              'cutover_authorized': False, 'production_qualified': False,
              'limitations': ['OFFLINE_UNAUTHENTICATED_EVIDENCE','NO_EFFECTIVE_ACCESS_PROOF',
                              'NO_CROSS_PROTOCOL_TRANSLATION','NO_VENDOR_CERTIFICATION']}
    return {'report':report,'sha256':_hash(report)}

def verify_migration_acl_risk(bundle, migration_id, datasets):
    if bundle != assess_migration_acl_risk(migration_id, datasets):
        raise MigrationACLRiskError('REPORT_MISMATCH')
    return True
