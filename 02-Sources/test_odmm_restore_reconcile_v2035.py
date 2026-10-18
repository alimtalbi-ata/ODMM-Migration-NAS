import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_restore_journal_v2034 import append
from odmm_restore_reconcile_v2035 import inspect,record_review

class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name);self.j=self.root/'journal.sqlite';self.dst=self.root/'restored.sqlite'
    def intent(self):append(self.j,'op','INTENT',{'destination':str(self.dst)})
    def test_unknown(self):self.assertEqual(inspect(self.j,'op')['status'],'UNKNOWN')
    def test_missing(self):self.intent();self.assertEqual(inspect(self.j,'op')['status'],'MISSING_DESTINATION')
    def test_present_not_verified(self):self.intent();self.dst.write_bytes(b'data');self.assertEqual(inspect(self.j,'op')['status'],'PRESENT_UNVERIFIED')
    def test_matching_digest_not_certification(self):
        self.intent();self.dst.write_bytes(b'data');d=hashlib.sha256(b'data').hexdigest()
        r=inspect(self.j,'op',expected_sha256=d);self.assertEqual(r['status'],'PRESENT_DIGEST_MATCH_UNVERIFIED');self.assertFalse(r['cutover_authorized'])
    def test_wrong_digest(self):self.intent();self.dst.write_bytes(b'data');self.assertEqual(inspect(self.j,'op',expected_sha256='0'*64)['status'],'DIGEST_MISMATCH')
    def test_conflicting_destination(self):self.intent();self.assertEqual(inspect(self.j,'op',expected_destination='other')['status'],'CONFLICT')
    def test_symlink(self):self.intent();self.dst.symlink_to(self.j);self.assertEqual(inspect(self.j,'op')['status'],'UNSAFE_DESTINATION')
    def test_closed(self):self.intent();append(self.j,'op','FAILED');self.assertEqual(inspect(self.j,'op')['status'],'CLOSED_FAILED')
    def test_tamper(self):
        self.intent()
        with sqlite3.connect(self.j) as c:c.execute("UPDATE restore_events SET phase='FAILED'")
        with self.assertRaisesRegex(ValueError,'JOURNAL_CORRUPT'):inspect(self.j,'op')
    def test_review_keeps_pending(self):
        self.intent();r=record_review(self.j,'op',reviewer='operator',comment='review needed')
        self.assertEqual(r['status'],'MISSING_DESTINATION')
    def test_no_auto_close(self):self.intent();self.assertTrue(inspect(self.j,'op')['requires_manual_approval'])
    def test_bad_reviewer(self):
        self.intent()
        with self.assertRaises(ValueError):record_review(self.j,'op',reviewer='',comment='x')
    def test_bad_digest(self):
        with self.assertRaises(ValueError):inspect(self.j,'op',expected_sha256='abc')
if __name__=='__main__':unittest.main()
