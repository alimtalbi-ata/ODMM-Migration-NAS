import unittest
from ldap_readonly_adapter import collect_readonly_snapshot, LDAPReadError

class Client:
    def __init__(self,pages): self.pages=iter(pages); self.calls=[]
    def search(self,*args): self.calls.append(args); return next(self.pages)

def entry(i='id-1',uac=0,groups=None):
    return {'entryUUID':i,'uid':'alice','userAccountControl':uac,'memberOf':groups if groups is not None else ['CN=ODMM_SECURITY_REVIEWERS']}
def page(entries=None,cookie=None,complete=True):
    return {'entries':entries if entries is not None else [entry()], 'next_cookie':cookie,'complete':complete}
def run(pages,**kwargs):
    return collect_readonly_snapshot(endpoint=kwargs.pop('endpoint','ldaps://directory.example:636'),base_dn='dc=example,dc=org',version='v1',client=Client(pages),**kwargs)

class TestLDAP(unittest.TestCase):
    def test_single_page(self):
        r=run([page()]); self.assertEqual(r['normalized']['accounts'][0]['role'],'security'); self.assertFalse(r['authenticated'])
    def test_disabled(self): self.assertFalse(run([page([entry(uac=2)])])['normalized']['accounts'][0]['active'])
    def test_unknown_group_unprivileged(self): self.assertFalse(run([page([entry(groups=['CN=OTHER'])])])['normalized']['accounts'][0]['active'])
    def test_two_pages(self):
        r=run([page([entry()], 'p2',False),page([entry('id-2')])]); self.assertEqual(len(r['normalized']['accounts']),2)
    def test_plain_ldap_rejected(self):
        with self.assertRaises(LDAPReadError): run([page()],endpoint='ldap://directory.example')
    def test_embedded_credentials_rejected(self):
        with self.assertRaises(LDAPReadError): run([page()],endpoint='ldaps://user:pass@directory.example')
    def test_incomplete(self):
        with self.assertRaises(LDAPReadError): run([page(complete=False)])
    def test_duplicate(self):
        with self.assertRaises(LDAPReadError): run([page([entry(),entry()])])
    def test_cookie_loop(self):
        with self.assertRaises(LDAPReadError): run([page(cookie='a',complete=False),page(cookie='a',complete=False)])
    def test_page_limit(self):
        with self.assertRaises(LDAPReadError): run([page(cookie='next',complete=False)],max_pages=1)
    def test_conflicting_groups(self):
        with self.assertRaises(LDAPReadError): run([page([entry(groups=list(('CN=ODMM_SECURITY_REVIEWERS','CN=ODMM_OPERATIONS_REVIEWERS')))])])
    def test_no_cutover(self): self.assertFalse(run([page()])['cutover_authorized'])
