"""Strict read-only LDAP snapshot bridge to offline campaign. Author: Abdelhalim Talbi.

An injected LDAP client is NOT proof of TLS, authentication or freshness.
"""
import hashlib
import json
from ldap_readonly_adapter import collect_readonly_snapshot
from odmm_group_campaign_v2190 import build_group_campaign

class DirectoryCampaignError(ValueError):
    pass

def reconcile_ldap_campaign(*, endpoint, base_dn, version, client, records, groups, identities):
    snapshot = collect_readonly_snapshot(endpoint=endpoint, base_dn=base_dn,
                                         version=version, client=client)
    campaign = build_group_campaign(records, groups, identities)
    # Never infer identity from UID, DN or group label: only exact stable IDs.
    # The legacy adapter intentionally reduces memberOf to privileged reviewer roles.
    # Its normalized output cannot prove arbitrary AD/LDAP memberships. Refuse
    # to equate the reduced representation with a complete directory group graph.
    normalized = snapshot.get('normalized')
    if not isinstance(normalized, dict) or not isinstance(normalized.get('accounts'), list):
        raise DirectoryCampaignError('DIRECTORY_SNAPSHOT_INVALID')
    reviewers = normalized['accounts']
    if len(reviewers) != len(identities) or {a.get('reviewer') for a in reviewers} != set(identities):
        raise DirectoryCampaignError('DIRECTORY_IDENTITY_SET_MISMATCH')
    # An account marked inactive or a reviewer role cannot attest general-purpose
    # nested groups. This bridge emits an explicit pending state, never a pass.
    membership_status = 'PENDING_FULL_MEMBERSHIP_COLLECTOR'
    payload = {'schema':'odmm.ldap-campaign.v2191',
               'campaign_sha256':campaign['sha256'],
               'directory_snapshot_sha256':hashlib.sha256(json.dumps(snapshot,sort_keys=True,default=str).encode()).hexdigest(),
               'identities_checked':len(identities),
               'direct_membership_equal':False,
               'membership_status':membership_status,
               'transport_authenticated':False,
               'directory_membership_attested':False,
               'effective_nas_acl_verified':False,
               'cutover_authorized':False,
               'limitations':['INJECTED_CLIENT_NOT_LIVE_AUTH_PROOF','DIRECT_GROUPS_ONLY','NO_NAS_TEST']}
    return {'report':payload,'sha256':hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
