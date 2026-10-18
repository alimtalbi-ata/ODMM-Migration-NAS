import copy
import tempfile
import unittest
from pathlib import Path
from native_benchmark_evidence_manifest import create_manifest
from native_benchmark_cockpit_panel import cockpit_panel, cockpit_status

class CockpitPanelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = b'P'*32
        self.manifest = create_manifest(self.root/'missing.jsonl', self.root,
            keys={'k1': b'A'*32}, manifest_key=self.key, key_id='panel')
    def panel(self, manifest=None, **kwargs):
        return cockpit_panel(manifest or self.manifest, manifest_keys={'panel': self.key}, **kwargs)
    def test_empty(self):
        self.assertIn('Intégrité des preuves', self.panel())
        self.assertIn('EMPTY', self.panel())
    def test_readonly_status(self):
        s = cockpit_status(self.manifest, manifest_keys={'panel': self.key})
        self.assertTrue(s['read_only'])
        self.assertFalse(s['cutover_authorized'])
    def test_bad_key(self):
        with self.assertRaises(ValueError): cockpit_panel(self.manifest, manifest_keys={'panel': b'X'*32})
    def test_tamper(self):
        bad = copy.deepcopy(self.manifest)
        bad['payload']['status'] = 'VERIFIED'
        with self.assertRaises(ValueError): self.panel(bad)
    def test_external_digest(self):
        with self.assertRaises(ValueError): self.panel(trusted_manifest_sha256='0'*64)
    def test_escaping(self):
        from native_benchmark_evidence_manifest import canonical
        import hmac,hashlib
        bad = copy.deepcopy(self.manifest)
        bad['payload']['stages']['entries'] = [{'name':'<script>alert(1)</script>', 'status':'PRESERVED','bytes':1,'sha256':'x'}]
        body = {k:v for k,v in bad.items() if k != 'hmac_sha256'}
        bad['hmac_sha256'] = hmac.new(self.key, canonical(body), hashlib.sha256).hexdigest()
        rendered = self.panel(bad)
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)
    def test_no_write(self):
        before = sorted(p.name for p in self.root.iterdir())
        self.panel()
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))

if __name__ == '__main__': unittest.main()
