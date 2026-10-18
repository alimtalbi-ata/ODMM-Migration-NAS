"""Local JWKS trust health regression. Author: Abdelhalim Talbi."""
import json
import tempfile
import unittest
from pathlib import Path
from test_odmm_oidc_rotation_outage_v1992 import pair
from odmm_oidc_jwks_health_v1993 import inspect
class HealthTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/'jwks.json'
        self.key=pair('current')[1]
    def write(self,keys):
        self.path.write_text(json.dumps({'keys':keys}));self.path.chmod(0o600)
    def probe(self):return inspect(issuer='https://id.example/realm',audience='odmm',jwks_path=self.path)
    def test_healthy(self):
        self.write([self.key]);r=self.probe()
        self.assertEqual(r['status'],'HEALTHY_LOCAL_JWKS')
        self.assertFalse(r['production_qualified'])
        self.assertNotIn('keys', r.get('error_code',''))
    def test_missing(self):self.assertEqual(self.probe()['status'],'UNHEALTHY_LOCAL_JWKS')
    def test_invalid_json(self):
        self.path.write_text('{bad');self.assertEqual(self.probe()['status'],'UNHEALTHY_LOCAL_JWKS')
    def test_duplicate_kid(self):
        self.write([self.key,self.key]);self.assertEqual(self.probe()['status'],'UNHEALTHY_LOCAL_JWKS')
    def test_recovery(self):
        self.assertEqual(self.probe()['status'],'UNHEALTHY_LOCAL_JWKS')
        self.write([self.key]);self.assertEqual(self.probe()['status'],'HEALTHY_LOCAL_JWKS')
    def test_unsafe_permissions(self):
        self.write([self.key]);self.path.chmod(0o666)
        self.assertEqual(self.probe()['status'],'UNHEALTHY_LOCAL_JWKS')
if __name__=='__main__':unittest.main()
