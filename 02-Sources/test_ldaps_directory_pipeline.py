import tempfile,unittest
from pathlib import Path
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
from directory_snapshot_adapter import normalize_directory_export
from ldaps_directory_pipeline import import_ldaps_directory, LDAPSImportError

ARGS=dict(endpoint='ldaps://directory.example:636',base_dn='dc=example',version='v1',
          bind_dn='cn=svc',password='secret',ca_file='/tmp/ca.pem',now=100)

def collector(*,version,**kw):
    b=normalize_directory_export({'source':'LDAP_EXPORT','version':version,'accounts':[
        {'id':'alice','enabled':True,'groups':['ODMM_SECURITY_REVIEWERS']},
        {'id':'bob','enabled':True,'groups':['ODMM_OPERATIONS_REVIEWERS']}]})
    return {**b,'transport':'LDAPS_TLS_CA_VALIDATED_BY_CLIENT'}

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ledger=AtomicDirectoryQuarantineLedger(str(Path(self.tmp.name)/'db.sqlite'),issuer_secret=b'a'*32)
        self.addCleanup(self.ledger.db.close)
    def run_import(self,**changes):
        return import_ldaps_directory(self.ledger,**{**ARGS,'collector':collector,**changes})
    def test_success(self):
        r=self.run_import();self.assertEqual(r['status'],'LDAPS_SNAPSHOT_ATOMICALLY_APPLIED')
        self.assertFalse(r['cutover_authorized']);self.assertFalse(r['directory_authenticated'])
        self.assertEqual(self.ledger.db.execute('SELECT count(*) FROM reviewer_directory').fetchone()[0],2)
    def test_cas_required_for_second_import(self):
        self.run_import()
        with self.assertRaises(Exception): self.run_import(version='v2')
    def test_cas_success(self):
        first=self.run_import();second=self.run_import(version='v2',expected_previous_digest=first['sha256'])
        self.assertNotEqual(first['sha256'],second['sha256'])
    def test_network_failure_does_not_mutate(self):
        def broken(**kw): raise OSError('network down')
        with self.assertRaises(OSError): self.run_import(collector=broken)
        self.assertEqual(self.ledger.db.execute('SELECT count(*) FROM reviewer_directory').fetchone()[0],0)
    def test_partial_page_failure_does_not_mutate(self):
        def broken(**kw): raise ValueError('LDAP_PAGE_LIMIT_EXCEEDED')
        with self.assertRaises(ValueError): self.run_import(collector=broken)
        self.assertEqual(self.ledger.db.execute('SELECT count(*) FROM reviewer_directory').fetchone()[0],0)
    def test_bad_digest_rejected(self):
        def bad(**kw): return {**collector(**kw),'sha256':'0'*64}
        with self.assertRaises(LDAPSImportError): self.run_import(collector=bad)
    def test_transport_claim_required(self):
        def bad(**kw): return {**collector(**kw),'transport':'INJECTED_CLIENT_TLS_UNVERIFIED'}
        with self.assertRaises(LDAPSImportError): self.run_import(collector=bad)
    def test_authentication_claim_rejected(self):
        def bad(**kw): return {**collector(**kw),'authenticated':True}
        with self.assertRaises(LDAPSImportError): self.run_import(collector=bad)
    def test_no_cutover_claim(self):
        def bad(**kw): return {**collector(**kw),'cutover_authorized':True}
        with self.assertRaises(LDAPSImportError): self.run_import(collector=bad)
    def test_invalid_time(self):
        with self.assertRaises(LDAPSImportError): self.run_import(now=-1)
    def test_invalid_cas(self):
        with self.assertRaises(LDAPSImportError): self.run_import(expected_previous_digest='bad')
    def test_no_accounts(self):
        def bad(**kw): return {**collector(**kw),'normalized':{'source':'LDAP_EXPORT','version':'v1','accounts':[]}}
        with self.assertRaises(Exception): self.run_import(collector=bad)
