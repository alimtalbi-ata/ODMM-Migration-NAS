"""Bind offline nested-group preflight to local identity campaign evidence.
Author: Abdelhalim Talbi. No live AD/LDAP or cutover qualification.
"""
import hashlib
import json
from odmm_group_membership_v2189 import preflight_group_graph
from odmm_identity_regression_report_v2188 import build_identity_regression_report

class GroupCampaignError(ValueError):
    pass

def _digest(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()

def build_group_campaign(records, groups, identities):
    """Reject any unproven identity/group label; keep mismatch evidence and deny cutover."""
    preflight = preflight_group_graph(groups, identities)
    regression = build_identity_regression_report(records)
    resolved = preflight['report']['resolved_groups']
    identities_set = set(identities)
    expected = {u: sorted(g for g, members in resolved.items() if u in members) for u in identities_set}
    cases = []
    for case in regression['report']['cases']:
        user = case['identity_ref']
        if user not in identities_set:
            raise GroupCampaignError('UNRESOLVED_IDENTITY')
        declared = case['group_refs']
        if declared != expected[user]:
            raise GroupCampaignError('GROUP_MEMBERSHIP_MISMATCH')
        cases.append({'case_id': case['case_id'], 'identity_ref': user,
                      'group_refs': declared, 'direction': case['direction'],
                      'local_open_outcomes_equal': case['local_open_outcomes_equal']})
    payload = {'schema': 'odmm.group-campaign.v2190',
               'group_preflight_sha256': preflight['sha256'],
               'identity_regression_sha256': regression['sha256'],
               'cases': cases, 'case_count': len(cases),
               'local_outcome_mismatch_count': regression['report']['local_outcome_mismatch_count'],
               'directory_membership_attested': False, 'ad_ldap_authentication_verified': False,
               'effective_nas_acl_verified': False, 'cutover_authorized': False,
               'limitations': ['OFFLINE_GROUP_GRAPH_ONLY', 'NO_LIVE_DIRECTORY_BIND', 'NO_NAS_QUALIFICATION']}
    return {'report': payload, 'sha256': _digest(payload)}
