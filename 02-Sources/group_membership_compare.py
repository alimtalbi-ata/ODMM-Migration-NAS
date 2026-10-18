"""Fail-closed offline source/target group comparison; never certifies access."""
import hashlib
import json
from identity_mapping_matrix import _identity, verify_mapping_matrix, MappingMatrixError
from nested_group_review import verify_nested_group_review, NestedGroupError

class GroupComparisonError(ValueError): pass

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()

def compare_group_memberships(mapping_bundle, source_bundle, target_bundle, source_snapshots, target_snapshots):
    try:
        verify_mapping_matrix(mapping_bundle)
        verify_nested_group_review(source_bundle, source_snapshots)
        verify_nested_group_review(target_bundle, target_snapshots)
    except (MappingMatrixError, NestedGroupError, TypeError, KeyError, ValueError) as exc:
        raise GroupComparisonError('UNVERIFIED_INPUT') from exc
    mapping=mapping_bundle['report']
    if mapping['status']=='BLOCKED':
        raise GroupComparisonError('AMBIGUOUS_MAPPING')
    forwards={}; backwards={}
    for pair in mapping['entries']:
        source=_identity(pair['source']); target=_identity(pair['target'])
        if source in forwards or target in backwards:
            raise GroupComparisonError('AMBIGUOUS_MAPPING')
        forwards[source]=target; backwards[target]=source
    sf={tuple(f['subject']):f for f in source_bundle['report']['findings']}
    tf={tuple(f['subject']):f for f in target_bundle['report']['findings']}
    findings=[]
    for user in sorted(sf):
        target_user=forwards.get(user)
        left=sf[user]
        right=tf.get(target_user) if target_user else None
        missing=[]; unexpected=[]; unmapped=[]
        if target_user is None or right is None:
            status='INDETERMINATE_IDENTITY'
        elif left['status']!='DECLARED_ONLY' or right['status']!='DECLARED_ONLY':
            status='INDETERMINATE_GROUP_GRAPH'
        else:
            mapped=set()
            for group in left['groups']:
                identity=tuple(group)
                if identity not in forwards:
                    unmapped.append(list(identity))
                else: mapped.add(forwards[identity])
            observed={tuple(g) for g in right['groups']}
            missing=[list(g) for g in sorted(mapped-observed)]
            unexpected=[list(g) for g in sorted(observed-mapped)]
            status=('INDETERMINATE_MAPPING' if unmapped else
                    'BLOCKED_PRIVILEGE_DRIFT' if missing or unexpected else 'DECLARED_MATCH_ONLY')
        findings.append({'source_user':list(user),'target_user':list(target_user) if target_user else None,
                         'status':status,'missing_target_groups':missing,'unexpected_target_groups':unexpected,
                         'unmapped_source_groups':unmapped})
    orphan_target_users=[list(k) for k in sorted(set(tf)-{forwards[u] for u in sf if u in forwards})]
    report={'schema':'odmm.group-membership-compare.v1','findings':findings,
            'unmatched_target_users':orphan_target_users,
            'status':'BLOCKED' if orphan_target_users or any(f['status']=='BLOCKED_PRIVILEGE_DRIFT' for f in findings) else 'PENDING_VERIFICATION',
            'directory_verified':False,'effective_access_verified':False,'production_qualified':False,
            'limitations':['OFFLINE_UNAUTHENTICATED_SNAPSHOTS','NO_LIVE_DIRECTORY_QUERY','NO_EFFECTIVE_ACCESS_CERTIFICATION']}
    return {'report':report,'sha256':_digest(report)}

def verify_group_comparison(bundle, *args):
    if not isinstance(bundle,dict) or bundle != compare_group_memberships(*args):
        raise GroupComparisonError('REPORT_MISMATCH')
    return True
