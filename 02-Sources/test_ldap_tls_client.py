import unittest
from ldap_tls_client import LDAPSReadClient, collect_ldaps_snapshot, LDAPTransportError

class FakeLDAP:
    NONE=object(); SIMPLE=object(); SUBTREE=object()
    class Tls:
        def __init__(self,**kw): self.kw=kw
    class Server:
        def __init__(self,*a,**kw): self.kw=kw
    class Connection:
        def __init__(self,*a,**kw):
            self.kw=kw; self.response=[]; self.result={}; self.closed=False
        def search(self,**kw):
            self.last_search=kw
            self.response=[{'type':'searchResEntry','attributes':{'entryUUID':'id1','uid':'alice','userAccountControl':0,'memberOf':['CN=ODMM_SECURITY_REVIEWERS']}}]
            self.result={'controls':{'1.2.840.113556.1.4.319':{'value':{'cookie':b''}}}}
            return True
        def unbind(self): self.closed=True

PARAMS=dict(endpoint='ldaps://example.org:636',bind_dn='cn=svc,dc=example,dc=org',password='secret',ca_file='/tmp/ca.pem',ldap_module=FakeLDAP)
class Tests(unittest.TestCase):
    def test_success(self):
        r=collect_ldaps_snapshot(**PARAMS,base_dn='dc=example,dc=org',version='v1')
        self.assertEqual(r['normalized']['accounts'][0]['role'],'security')
        self.assertFalse(r['cutover_authorized'])
    def test_ca_required(self):
        with self.assertRaises(LDAPTransportError): LDAPSReadClient(**{**PARAMS,'ca_file':''})
    def test_plaintext_rejected(self):
        with self.assertRaises(LDAPTransportError): LDAPSReadClient(**{**PARAMS,'endpoint':'ldap://example.org'})
    def test_embedded_password_rejected(self):
        with self.assertRaises(LDAPTransportError): LDAPSReadClient(**{**PARAMS,'endpoint':'ldaps://a:b@example.org'})
    def test_timeout_rejected(self):
        with self.assertRaises(LDAPTransportError): LDAPSReadClient(**{**PARAMS,'timeout':0})
    def test_page_size_rejected(self):
        with self.assertRaises(LDAPTransportError): LDAPSReadClient(**{**PARAMS,'page_size':0})
    def test_tls_validation(self):
        import ssl
        c=LDAPSReadClient(**PARAMS)
        self.assertEqual(c._server.kw['tls'].kw['validate'],ssl.CERT_REQUIRED)
        self.assertTrue(c._server.kw['use_ssl'])
    def test_readonly_search(self):
        with LDAPSReadClient(**PARAMS) as c:
            p=c.search('dc=example,dc=org','(objectClass=person)',('uid',),None)
            self.assertTrue(p['complete']); self.assertEqual(len(p['entries']),1)
            self.assertFalse(c._conn.kw['auto_referrals'])
    def test_unbound_rejected(self):
        c=LDAPSReadClient(**PARAMS)
        with self.assertRaises(LDAPTransportError): c.search('base','filter',(),None)
    def test_bind_error(self):
        class Bad(FakeLDAP):
            class Connection:
                def __init__(self,*a,**kw): raise RuntimeError('bind')
        with self.assertRaises(LDAPTransportError):
            with LDAPSReadClient(**{**PARAMS,'ldap_module':Bad}): pass
