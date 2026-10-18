import tempfile
import unittest
from pathlib import Path
from native_benchmark_cockpit_adapter import serve_evidence
from native_benchmark_evidence_manifest import create_manifest

class CockpitAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / 'access.sqlite'
        self.keys = {'k1': b'A'*32}
        self.manifest_keys = {'m1': b'B'*32}
        self.manifest = create_manifest(self.root/'missing.jsonl', self.root, keys=self.keys,
                                        manifest_key=self.manifest_keys['m1'], key_id='m1')
        self.user = {'authenticated': True, 'subject': 'tester', 'roles': ['evidence_viewer']}
    def call(self, **kw):
        return serve_evidence(self.manifest, principal=self.user, manifest_keys=self.manifest_keys,
                              audit_db=self.db, audit_key=b'C'*32, **kw)
    def test_json(self):
        mime, body = self.call()
        self.assertEqual(mime, 'application/json; charset=utf-8')
        self.assertTrue(__import__('json').loads(body)['read_only'])
    def test_html(self):
        mime, body = self.call(representation='html')
        self.assertIn(b'odmm-evidence-panel', body)
    def test_audit_both_reads(self):
        self.call(); self.call(representation='html')
        import sqlite3
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute('select count(*) from evidence_access_log').fetchone()[0], 2)
    def test_no_auth(self):
        self.user['authenticated'] = False
        with self.assertRaises(PermissionError): self.call()
        self.assertFalse(self.db.exists())
    def test_no_role(self):
        self.user['roles'] = ['guest']
        with self.assertRaises(PermissionError): self.call()
    def test_tampered_manifest(self):
        self.manifest['payload']['status'] = 'CLEAR'
        with self.assertRaises(ValueError): self.call()
        self.assertFalse(self.db.exists())
    def test_audit_failure_blocks_disclosure(self):
        with self.assertRaises(Exception):
            serve_evidence(self.manifest, principal=self.user, manifest_keys=self.manifest_keys, audit_db=self.root/'nonexistent'/'audit.db', audit_key=b'C'*32)
    def test_unknown_format(self):
        with self.assertRaises(ValueError): self.call(representation='xml')
    def test_bad_trusted_digest(self):
        with self.assertRaises(ValueError): self.call(trusted_manifest_sha256='0'*64)
    def test_audit_hmac_tamper_blocks(self):
        import sqlite3
        self.call()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE evidence_access_log SET action='forged' WHERE id=1")
        with self.assertRaisesRegex(ValueError, 'AUDIT_CHAIN_INVALID'): self.call()

    def test_audit_wrong_key_blocks(self):
        from native_benchmark_cockpit_adapter import serve_evidence
        self.call()
        with self.assertRaisesRegex(ValueError, 'AUDIT_CHAIN_INVALID'):
            serve_evidence(self.manifest, principal=self.user, manifest_keys=self.manifest_keys,
                           audit_db=self.db, audit_key=b'Z'*32)

    def test_audit_trusted_head_mismatch(self):
        self.call()
        with self.assertRaisesRegex(ValueError, 'AUDIT_TRUSTED_HEAD_MISMATCH'):
            self.call(trusted_audit_head='0'*64)

    def test_audit_key_required(self):
        from native_benchmark_cockpit_adapter import serve_evidence
        with self.assertRaisesRegex(ValueError, 'AUDIT_KEY_REQUIRED'):
            serve_evidence(self.manifest, principal=self.user, manifest_keys=self.manifest_keys,
                           audit_db=self.db, audit_key=b'weak')

    def test_audit_symlink_refused(self):
        target = self.root / 'real.sqlite'
        link = self.root / 'link.sqlite'
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'AUDIT_PATH_SYMLINK'):
            from native_benchmark_cockpit_adapter import serve_evidence
            serve_evidence(self.manifest, principal=self.user, manifest_keys=self.manifest_keys,
                           audit_db=link, audit_key=b'C'*32)
        self.assertFalse(target.exists())

    def test_audit_missing_sequence_blocks(self):
        import sqlite3
        self.call(); self.call()
        with sqlite3.connect(self.db) as conn:
            conn.execute('DELETE FROM evidence_access_log WHERE id=1')
        with self.assertRaisesRegex(ValueError, 'AUDIT_CHAIN_INVALID'): self.call()

    def test_no_mutation_of_evidence(self):
        before = repr(self.manifest)
        self.call()
        self.assertEqual(repr(self.manifest), before)
if __name__ == '__main__': unittest.main()
