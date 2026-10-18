import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_restore_journal_v2034 import append
from odmm_reconcile_guard_v2036 import inspect_locked,review_locked,verify_readonly

def writer(path,n):
    for i in range(n):append(path,'op','VERIFIED',{'i':i})

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.j=Path(self.tmp.name)/'journal.db'
    def test_missing_readonly(self):
        with self.assertRaises(ValueError):verify_readonly(self.j)
        self.assertFalse(self.j.exists())
    def test_valid_readonly(self):
        append(self.j,'op','INTENT',{'destination':'/tmp/nonexistent'})
        self.assertEqual(verify_readonly(self.j)['events'],1)
    def test_missing_destination(self):
        append(self.j,'op','INTENT',{'destination':str(Path(self.tmp.name)/'absent')})
        self.assertEqual(inspect_locked(self.j,'op')['status'],'MISSING_DESTINATION')
    def test_manual_review(self):
        append(self.j,'op','INTENT',{'destination':str(Path(self.tmp.name)/'absent')})
        self.assertTrue(review_locked(self.j,'op',reviewer='admin',comment='manual')['requires_manual_approval'])
        self.assertEqual(verify_readonly(self.j)['events'],2)
    def test_unknown(self):
        append(self.j,'known','INTENT')
        with self.assertRaises(ValueError):review_locked(self.j,'other',reviewer='admin',comment='manual')
    def test_tamper(self):
        append(self.j,'op','INTENT')
        with sqlite3.connect(self.j) as c:c.execute("UPDATE restore_events SET phase='FAILED'")
        with self.assertRaisesRegex(ValueError,'JOURNAL_CORRUPT'):verify_readonly(self.j)
    def test_concurrent_writers(self):
        processes=[multiprocessing.Process(target=writer,args=(str(self.j),6)) for _ in range(3)]
        for proc in processes:proc.start()
        for proc in processes:proc.join(15);self.assertEqual(proc.exitcode,0)
        self.assertEqual(verify_readonly(self.j)['events'],18)
    def test_safety(self):
        append(self.j,'op','INTENT')
        r=inspect_locked(self.j,'op')
        self.assertFalse(r['cutover_authorized']);self.assertFalse(r['writes_to_nas'])
if __name__=='__main__':unittest.main()
