import pytest
from odmm_ldap_membership_v2192 import collect_memberships, MembershipCollectionError

U={'distinguishedName':'CN=Alice,DC=x','objectClass':['person'],'entryUUID':'u1','memberOf':['CN=Ops,DC=x']}
G={'distinguishedName':'CN=Ops,DC=x','objectClass':['group'],'member':['CN=Alice,DC=x']}
H={'distinguishedName':'CN=Admin,DC=x','objectClass':['group'],'member':['CN=Ops,DC=x']}
class Client:
    def __init__(self, pages): self.pages=iter(pages)
    def search(self, **kwargs): return next(self.pages)
def page(items, cookie=None): return {'entries':items,'next_cookie':cookie,'complete':not bool(cookie)}
def run(pages, **kw): return collect_memberships(endpoint='ldaps://directory.example',base_dn='DC=x',client=Client(pages),now=1000,observed_at=999,**kw)
def test_nested_and_paged():
    result=run([page([U], 'next'),page([G,H])]); assert result['report']['resolved_members']['cn=admin,dc=x']==['u1']; assert result['report']['pages']==2; assert not result['report']['cutover_authorized']
def test_stable_hash(): assert run([page([U,G])])['sha256']==run([page([G,U])])['sha256']
@pytest.mark.parametrize('pages', [[page([U])],[page([U,G,G])],[page([U,G], 'x'),page([], 'x')],[page([U,G], 'x')],[page([U,G,{'distinguishedName':'CN=Bad,DC=x','objectClass':['group'],'member':['CN=Unknown,DC=x']}])]])
def test_reject_invalid(pages):
    with pytest.raises(MembershipCollectionError): run(pages, max_pages=2)
def test_cycle():
    a=dict(H,member=['CN=Ops,DC=x']); b=dict(G,member=['CN=Alice,DC=x','CN=Admin,DC=x'])
    with pytest.raises(MembershipCollectionError, match='GROUP_CYCLE'): run([page([U,a,b])])
def test_stale():
    with pytest.raises(MembershipCollectionError,match='STALE'): run([page([U,G])],max_age_seconds=0.5)
def test_no_plain_ldap():
    with pytest.raises(MembershipCollectionError): collect_memberships(endpoint='ldap://host',base_dn='DC=x',client=Client([]))
