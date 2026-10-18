import shutil
import tempfile
import unittest
from pathlib import Path
from ldaps_witness_trust_validation import validate_trust, supervised_rollback_plan, TrustValidationError
from test_ldaps_remote_witness_mtls_e2e import MutualTLSIntegrationTests

@unittest.skipUnless(shutil.which('openssl'),'OpenSSL required')
class TrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MutualTLSIntegrationTests.setUpClass()
        cls.p=MutualTLSIntegrationTests.root
    @classmethod
    def tearDownClass(cls): MutualTLSIntegrationTests.tearDownClass()
    def check(self,**kwargs):
        return validate_trust(certfile=self.p/'server.crt',cafile=self.p/'ca.crt',expected_dns='localhost',**kwargs)
    def test_chain_valid(self):
        x=self.check();self.assertEqual(x['revocation'],'NOT_CHECKED');self.assertFalse(x['deployment_authorized'])
    def test_wrong_hostname(self):
        with self.assertRaises(TrustValidationError):validate_trust(certfile=self.p/'server.crt',cafile=self.p/'ca.crt',expected_dns='bad.example')
    def test_untrusted_ca(self):
        with self.assertRaises(TrustValidationError):validate_trust(certfile=self.p/'server.crt',cafile=self.p/'other.crt',expected_dns='localhost')
    def test_wrong_purpose(self):
        with self.assertRaises(TrustValidationError):validate_trust(certfile=self.p/'client.crt',cafile=self.p/'ca.crt',expected_dns='localhost')
    def test_missing_crl_fails_closed(self):
        with self.assertRaises(TrustValidationError):self.check(crlfile=self.p/'missing.crl')
    def test_malformed_crl_fails_closed(self):
        f=self.p/'broken.crl';f.write_text('broken');f.chmod(0o600)
        with self.assertRaises(TrustValidationError):self.check(crlfile=f)
    def test_invalid_policy(self):
        with self.assertRaises(TrustValidationError):validate_trust(certfile=self.p/'server.crt',cafile=self.p/'ca.crt',expected_dns='',timeout=2)
    def test_same_file_rejected(self):
        with self.assertRaises(TrustValidationError):validate_trust(certfile=self.p/'server.crt',cafile=self.p/'server.crt',expected_dns='localhost')
    def test_invalid_timeout(self):
        with self.assertRaises(TrustValidationError):validate_trust(certfile=self.p/'server.crt',cafile=self.p/'ca.crt',expected_dns='localhost',timeout=-1)
    def test_rollback_two_reviewers(self):
        with self.assertRaises(TrustValidationError):supervised_rollback_plan(prior_certificate_sha256='a'*64,failed_certificate_sha256='b'*64,operator_confirmed=True,second_reviewer_confirmed=False)
    def test_rollback_plan_read_only(self):
        p=supervised_rollback_plan(prior_certificate_sha256='a'*64,failed_certificate_sha256='b'*64,operator_confirmed=True,second_reviewer_confirmed=True)
        self.assertFalse(p['automatic_rollback']);self.assertFalse(p['automatic_restart'])
    def test_identical_fingerprint(self):
        with self.assertRaises(TrustValidationError):supervised_rollback_plan(prior_certificate_sha256='a'*64,failed_certificate_sha256='a'*64,operator_confirmed=True,second_reviewer_confirmed=True)
