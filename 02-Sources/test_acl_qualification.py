import os
import tempfile
import unittest
from pathlib import Path
from acl_qualification import acl_evidence, compare_acl_evidence, evidence_digest

class ACLQualificationTests(unittest.TestCase):
    def test_identical_files_remain_indeterminate(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=Path(d)/"a",Path(d)/"b"
            a.write_bytes(b"same"); b.write_bytes(b"same")
            r=compare_acl_evidence(a,b)
            self.assertEqual(r["status"],"INDETERMINATE")
            self.assertFalse(r["acl_fidelity_certified"])
            self.assertFalse(r["effective_access_verified"])
    def test_mode_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=Path(d)/"a",Path(d)/"b"
            a.touch(); b.touch(); a.chmod(0o600); b.chmod(0o644)
            self.assertIn("mode",compare_acl_evidence(a,b)["mismatches"])
    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/"a"; a.touch(); link=Path(d)/"link"; link.symlink_to(a)
            r=acl_evidence(link)
            self.assertIn("SYMLINK_UNSUPPORTED",r["errors"])
    def test_digest_deterministic(self):
        self.assertEqual(evidence_digest({"b":2,"a":1}),evidence_digest({"a":1,"b":2}))
    def test_digest_detects_tampering(self):
        self.assertNotEqual(evidence_digest({"mode":384}),evidence_digest({"mode":420}))

if __name__=="__main__": unittest.main()
