import tempfile
import unittest
from pathlib import Path
from odmm_secure_deploy import validate_deployment

class DeployGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths=[Path(self.tmp.name)/x for x in ('registry.db','grants.db','jwks.json')]
        for p in self.paths: p.write_text('{}')
    def check(self,host='127.0.0.1',paths=None):
        a,b,c=paths or self.paths
        return validate_deployment(host=host,registry_path=a,grants_path=b,jwks_path=c)
    def test_ipv4_local(self): self.assertTrue(self.check())
    def test_ipv6_local(self): self.assertTrue(self.check('::1'))
    def test_all_interfaces_rejected(self):
        with self.assertRaisesRegex(ValueError,'NON_LOOPBACK'): self.check('0.0.0.0')
    def test_remote_rejected(self):
        with self.assertRaisesRegex(ValueError,'NON_LOOPBACK'): self.check('192.0.2.1')
    def test_dns_rejected(self):
        with self.assertRaisesRegex(ValueError,'NUMERIC_LOOPBACK'): self.check('localhost')
    def test_symlink_rejected(self):
        alias=Path(self.tmp.name)/'alias'; alias.symlink_to(self.paths[2])
        with self.assertRaisesRegex(ValueError,'SYMLINK'): self.check(paths=[*self.paths[:2],alias])
    def test_missing_file_rejected(self):
        self.paths[2].unlink()
        with self.assertRaisesRegex(ValueError,'MUST_EXIST'): self.check()
    def test_same_file_rejected(self):
        with self.assertRaisesRegex(ValueError,'SEPARATE'): self.check(paths=[self.paths[0],self.paths[0],self.paths[2]])
    def test_world_writable_jwks_rejected(self):
        self.paths[2].chmod(0o666)
        with self.assertRaisesRegex(ValueError,'JWKS_WRITABLE'): self.check()
