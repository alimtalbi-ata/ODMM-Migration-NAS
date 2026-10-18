"""Fail-closed reconciliation of LDAPS membership evidence with ODMM campaigns.
Author: Abdelhalim Talbi. Does not certify NAS effective access.
"""
from odmm_ldap_membership_v2192 import _hash

class CampaignDirectoryMismatch(ValueError):
    pass

def reconcile_directory_campaign(directory_evidence, campaign_evidence, identity_to_dn, group_to_dn, *, now, max_age=300):
    if not isinstance(directory_evidence, dict) or not isinstance(campaign_evidence, dict):
        raise CampaignDirectoryMismatch('INVALID_EVIDENCE')
    directory = directory_evidence.get('report')
    campaign = campaign_evidence.get('report')
    if not isinstance(directory, dict) or not isinstance(campaign, dict):
        raise CampaignDirectoryMismatch('INVALID_REPORT')
    if directory_evidence.get('sha256') != _hash(directory) or campaign_evidence.get('sha256') != _hash(campaign):
        raise CampaignDirectoryMismatch('EVIDENCE_HASH_MISMATCH')
    if directory.get('schema') != 'odmm.ldap-membership.v2192' or campaign.get('schema') != 'odmm.group-campaign.v2190':
        raise CampaignDirectoryMismatch('UNSUPPORTED_SCHEMA')
    if directory.get('transport_authenticated') is not True or directory.get('directory_authenticated') is not True or directory.get('transport_mode') != 'LDAPS_CERT_REQUIRED':
        raise CampaignDirectoryMismatch('UNAUTHENTICATED_DIRECTORY')
    observed = directory.get('observed_at')
    if type(now) not in (int, float) or type(observed) not in (int, float) or not 0 <= now-observed <= max_age:
        raise CampaignDirectoryMismatch('STALE_DIRECTORY')
    if not isinstance(identity_to_dn, dict) or not isinstance(group_to_dn, dict):
        raise CampaignDirectoryMismatch('MAPPING_REQUIRED')
    if len(set(x.casefold() for x in identity_to_dn.values())) != len(identity_to_dn) or len(set(x.casefold() for x in group_to_dn.values())) != len(group_to_dn):
        raise CampaignDirectoryMismatch('AMBIGUOUS_MAPPING')
    accounts = directory.get('accounts', {})
    resolved = directory.get('resolved_members', {})
    if not isinstance(accounts, dict) or not isinstance(resolved, dict):
        raise CampaignDirectoryMismatch('INVALID_DIRECTORY')
    cases = campaign.get('cases', [])
    if not isinstance(cases, list) or set(identity_to_dn) != {c.get('identity_ref') for c in cases}:
        raise CampaignDirectoryMismatch('IDENTITY_SCOPE_MISMATCH')
    results = []
    for case in cases:
        identity = case['identity_ref']
        dn = identity_to_dn[identity].casefold()
        if dn not in accounts:
            raise CampaignDirectoryMismatch('IDENTITY_NOT_FOUND')
        uid = accounts[dn]['id']
        expected = sorted(g for g, group_dn in group_to_dn.items() if uid in resolved.get(group_dn.casefold(), []))
        declared = case.get('group_refs')
        if not isinstance(declared, list) or len(declared) != len(set(declared)):
            raise CampaignDirectoryMismatch('INVALID_GROUPS')
        results.append({'case_id':case['case_id'], 'identity_ref':identity, 'directory_uid':uid,
                        'declared_groups':declared, 'directory_groups':expected,
                        'groups_equal':declared == expected, 'local_access_equal':case['local_open_outcomes_equal']})
    payload = {'schema':'odmm.authenticated-campaign.v2194', 'directory_sha256':directory_evidence['sha256'],
               'campaign_sha256':campaign_evidence['sha256'], 'cases':results,
               'group_mismatch_count':sum(not r['groups_equal'] for r in results),
               'directory_transport_attested':True, 'nas_effective_access_verified':False,
               'cutover_authorized':False, 'limitations':['NO_AUTHENTICATED_NAS_EFFECTIVE_ACCESS_TEST']}
    return {'report':payload, 'sha256':_hash(payload)}
