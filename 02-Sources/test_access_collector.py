import unittest, tempfile
from pathlib import Path
from access_collector import collect_local, capability_report

class CollectorTests(unittest.TestCase):
    def test_local_evidence_stable(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'hello')
            a=collect_local(p,expected_root=d);b=collect_local(p,expected_root=d)
            self.assertEqual(a['evidence_sha256'],b['evidence_sha256'])
            self.assertEqual(a['status'],'OBSERVED_LOCAL_ONLY')
    def test_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_text('x');q=Path(d)/'link';q.symlink_to(p)
            self.assertEqual(collect_local(q)['status'],'BLOCKED_SYMLINK')
    def test_root_restriction(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            p=Path(outside)/'x';p.write_text('x')
            with self.assertRaises(ValueError): collect_local(p,expected_root=d)
    def test_protocols_fail_closed(self):
        for protocol in ('LOCAL_POSIX','NFSv3','NFSv4','SMB'):
            self.assertFalse(capability_report(protocol)['safe_for_cutover'])
    def test_unknown_protocol(self):
        with self.assertRaises(ValueError): capability_report('S3')
