import tempfile, unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from ldaps_witness_cert_rotation import inspect_candidate, supervised_rotation_plan, CertificateRotationError

class RotationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.p=Path(self.temp.name);self.now=datetime.now(timezone.utc)
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.make()
    def make(self, *, key=None, dns='witness.example', before=-1, after=90, eku=True):
        key=key or self.key
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'witness.example')])
        b=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(self.now+timedelta(days=before)).not_valid_after(self.now+timedelta(days=after)).add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]),critical=False)
        if eku:b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        cert=b.sign(key,hashes.SHA256())
        for name,content in [('cert',cert.public_bytes(serialization.Encoding.PEM)),('ca',cert.public_bytes(serialization.Encoding.PEM)),('key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))]:
            f=self.p/name;f.write_bytes(content);f.chmod(0o600)
    def check(self,**kw):
        return inspect_candidate(certfile=self.p/'cert',keyfile=self.p/'key',cafile=self.p/'ca',expected_dns='witness.example',now=self.now,**kw)
    def test_valid(self):self.assertEqual(self.check()['status'],'CANDIDATE_PREFLIGHT_OK')
    def test_expired(self):
        self.make(before=-90,after=-1)
        with self.assertRaises(CertificateRotationError):self.check()
    def test_not_yet_valid(self):
        self.make(before=1,after=90)
        with self.assertRaises(CertificateRotationError):self.check()
    def test_renewal_window(self):
        self.make(after=5)
        with self.assertRaises(CertificateRotationError):self.check()
    def test_wrong_dns(self):
        self.make(dns='other.example')
        with self.assertRaises(CertificateRotationError):self.check()
    def test_no_eku(self):
        self.make(eku=False)
        with self.assertRaises(CertificateRotationError):self.check()
    def test_mismatched_key(self):
        other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        (self.p/'key').write_bytes(other.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        with self.assertRaises(CertificateRotationError):self.check()
    def test_bad_ca(self):
        (self.p/'ca').write_text('invalid')
        with self.assertRaises(CertificateRotationError):self.check()
    def test_insecure_key(self):
        (self.p/'key').chmod(0o644)
        with self.assertRaises(CertificateRotationError):self.check()
    def test_symlink(self):
        (self.p/'ca').unlink();(self.p/'ca').symlink_to(self.p/'cert')
        with self.assertRaises(CertificateRotationError):self.check()
    def test_plan_requires_two_reviewers(self):
        with self.assertRaises(CertificateRotationError):supervised_rotation_plan(candidate=self.check(),operator_confirmed=True,second_reviewer_confirmed=False)
    def test_plan_never_deploys(self):
        plan=supervised_rotation_plan(candidate=self.check(),operator_confirmed=True,second_reviewer_confirmed=True)
        self.assertFalse(plan['automatic_restart']);self.assertFalse(plan['automatic_deployment'])
    def test_invalid_policy(self):
        with self.assertRaises(CertificateRotationError):self.check(minimum_days=-1)
