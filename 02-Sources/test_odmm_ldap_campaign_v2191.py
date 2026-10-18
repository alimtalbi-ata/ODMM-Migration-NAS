import pytest
from test_odmm_group_campaign_v2190 import record
from odmm_ldap_campaign_v2191 import reconcile_ldap_campaign, DirectoryCampaignError

class Client:
    def search(self, base, filt, attrs, cookie):
        return {'entries':[{'entryUUID':'alice','uid':'alice','userAccountControl':0,'memberOf':[]}],
                'next_cookie':None,'complete':True}

def test_pending_not_cutover():
    r=reconcile_ldap_campaign(endpoint='ldaps://example.org',base_dn='dc=example,dc=org',version='1',client=Client(),records=[record(user='alice',groups=())],groups={},identities=['alice'])
    assert r['report']['membership_status']=='PENDING_FULL_MEMBERSHIP_COLLECTOR'
    assert not r['report']['cutover_authorized']
    assert not r['report']['directory_membership_attested']

def test_unknown_directory_identity_rejected():
    with pytest.raises(DirectoryCampaignError,match='DIRECTORY_IDENTITY_SET_MISMATCH'):
        reconcile_ldap_campaign(endpoint='ldaps://example.org',base_dn='dc=example,dc=org',version='1',client=Client(),records=[record(user='bob',groups=())],groups={},identities=['bob'])

def test_no_plain_ldap():
    with pytest.raises(ValueError):
        reconcile_ldap_campaign(endpoint='ldap://example.org',base_dn='dc=example,dc=org',version='1',client=Client(),records=[record(user='alice',groups=())],groups={},identities=['alice'])
