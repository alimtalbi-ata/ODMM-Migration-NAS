"""Portable regression tests for the independent recovery evidence verifier."""
import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / '09-Tools' / 'VERIFY-RECOVERY-AUDIT.py'
spec = importlib.util.spec_from_file_location('odmm_recovery_audit_cli', CLI)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecoveryAuditCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'evidence.json'
        self.evidence = {
            'schema': 'odmm.native.recovery.audit.v1',
            'plan_id': 'test-plan',
            'tasks': [],
            'read_only': True,
            'automatic_reset': False,
            'cutover_authorized': False,
            'snapshot_consistent': False,
            'evidence_scope': 'sqlite_registry_observation_only',
        }
        canonical = json.dumps(self.evidence, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        self.evidence['sha256'] = hashlib.sha256(canonical).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self):
        return subprocess.run([sys.executable, str(CLI), str(self.path)],
                              capture_output=True, text=True, timeout=10)

    def test_valid_evidence(self):
        self.path.write_text(json.dumps(self.evidence), encoding='utf-8')
        self.assertTrue(module.verify_file(self.path))
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('unsigned', result.stdout)

    def test_tamper_detected(self):
        self.evidence['plan_id'] = 'forged'
        self.path.write_text(json.dumps(self.evidence), encoding='utf-8')
        self.assertFalse(module.verify_file(self.path))
        self.assertEqual(self.run_cli().returncode, 2)

    def test_missing_or_malformed(self):
        self.assertEqual(self.run_cli().returncode, 2)
        self.path.write_text('{broken', encoding='utf-8')
        self.assertEqual(self.run_cli().returncode, 2)

    def test_duplicate_keys_rejected(self):
        self.path.write_text('{"schema":"a","schema":"b"}', encoding='utf-8')
        self.assertEqual(self.run_cli().returncode, 2)

    def test_nonfinite_number_rejected(self):
        self.path.write_text('{"value":NaN}', encoding='utf-8')
        self.assertEqual(self.run_cli().returncode, 2)

    def test_nested_duplicate_keys_rejected(self):
        self.path.write_text('{"tasks":[{"path":"a","path":"b"}]}', encoding='utf-8')
        self.assertEqual(self.run_cli().returncode, 2)

    def test_oversized_input_rejected(self):
        self.path.write_bytes(b'x' * (8 * 1024 * 1024 + 1))
        self.assertFalse(module.verify_file(self.path))


if __name__ == '__main__':
    unittest.main()
