"""Adversarial delivery ZIP validation tests."""
import importlib.util
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('odmm_manifest_verify', ROOT / '09-Tools' / 'VERIFY-DELIVERY-MANIFEST.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ManifestSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'package.zip'

    def tearDown(self):
        self.temp.cleanup()

    def write(self, manifest, payload=b'data'):
        with zipfile.ZipFile(self.path, 'w') as z:
            z.writestr('data.txt', payload)
            z.writestr('DELIVERY-MANIFEST.json', manifest)

    def valid(self):
        return {'schema_version': 1, 'files': {'data.txt': hashlib.sha256(b'data').hexdigest()},
                'source_commit': 'test', 'source_type': 'git-checkout'}

    def test_valid(self):
        self.write(json.dumps(self.valid()))
        self.assertEqual(module.verify(self.path)['status'], 'PASS')

    def test_tampered_bytes(self):
        self.write(json.dumps(self.valid()), payload=b'forged')
        with self.assertRaises(ValueError):
            module.verify(self.path)

    def test_duplicate_json_keys(self):
        data = json.dumps(self.valid())
        self.write(data[:-1] + ',"schema_version":1}')
        with self.assertRaises(ValueError):
            module.verify(self.path)

    def test_invalid_digest_format(self):
        manifest = self.valid()
        manifest['files']['data.txt'] = 'not-a-hash'
        self.write(json.dumps(manifest))
        with self.assertRaises(ValueError):
            module.verify(self.path)

    def test_unknown_schema(self):
        manifest = self.valid()
        manifest['schema_version'] = 999
        self.write(json.dumps(manifest))
        with self.assertRaises(ValueError):
            module.verify(self.path)


if __name__ == '__main__':
    unittest.main()
