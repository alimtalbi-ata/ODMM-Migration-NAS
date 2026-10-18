import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from native_benchmark_authenticated import append_authenticated
from native_benchmark_evidence_manifest import create_manifest, verify_manifest, canonical


class ManifestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.journal = self.root / 'journal'
        self.keys = {'journal': b'J'*32}
        self.signing = b'M'*32
        append_authenticated(self.journal, {'schema': 'odmm.audit.mixed_benchmark.v1',
            'status': 'PASS', 'cutover_authorized': False, 'source_read_only': True,
            'isolated_copy': True}, keys=self.keys, key_id='journal')
        self.original = self.journal.read_bytes()
        self.manifest = create_manifest(self.journal, self.root, keys=self.keys,
                                        manifest_key=self.signing, key_id='m1')

    def verify(self, m=None, **kw):
        return verify_manifest(self.manifest if m is None else m,
                               manifest_keys={'m1': self.signing}, **kw)

    def test_valid_manifest(self):
        self.assertEqual(self.verify()['status'], 'AUTHENTICATED')
        self.assertEqual(self.original, self.journal.read_bytes())

    def test_canonical_roundtrip(self):
        import json
        m = json.loads(canonical(self.manifest))
        self.assertEqual(self.verify(m)['status'], 'AUTHENTICATED')

    def test_payload_tamper_rejected(self):
        m = copy.deepcopy(self.manifest); m['payload']['status'] = 'CLEAR'
        with self.assertRaisesRegex(ValueError, 'AUTHENTICATION'): self.verify(m)

    def test_stage_tamper_rejected(self):
        (self.root/'.odmm-stage-test').write_bytes(b'partial')
        m = create_manifest(self.journal, self.root, keys=self.keys,
                            manifest_key=self.signing, key_id='m1')
        m['payload']['stages']['entries'][0]['sha256'] = '0'*64
        with self.assertRaises(ValueError): self.verify(m)

    def test_wrong_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'AUTHENTICATION'):
            verify_manifest(self.manifest, manifest_keys={'m1': b'X'*32})

    def test_missing_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'UNAVAILABLE'):
            verify_manifest(self.manifest, manifest_keys={})

    def test_short_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'KEY_INVALID'):
            create_manifest(self.journal, self.root, keys=self.keys,
                            manifest_key=b'short', key_id='m1')

    def test_trusted_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'TRUSTED_DIGEST'):
            self.verify(trusted_manifest_sha256='0'*64)

    def test_trusted_digest_accepted(self):
        digest = hashlib.sha256(canonical(self.manifest)).hexdigest()
        self.assertEqual(self.verify(trusted_manifest_sha256=digest)['sha256'], digest)

    def test_no_authorization(self):
        self.assertFalse(self.verify()['cutover_authorized'])
        self.assertFalse(self.verify()['cleanup_authorized'])

    def test_unsafe_flags_rejected(self):
        m = copy.deepcopy(self.manifest); m['cutover_authorized'] = True
        with self.assertRaises(ValueError): self.verify(m)

    def test_extra_fields_rejected(self):
        m = copy.deepcopy(self.manifest); m['injected'] = True
        with self.assertRaises(ValueError): self.verify(m)
