import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_restore_journal_v2034 import append, verify, advisory_lock
from odmm_crash_recovery_v2037 import assess

def crashed_writer(journal):
    # Simulate a power-loss-style abrupt process exit while SQLite transaction is open.
    con=sqlite3.connect(journal,timeout=10,isolation_level=None)
    con.execute('BEGIN IMMEDIATE')
    con.execute("INSERT INTO restore_events(operation,phase,payload,prev_hash,event_hash) VALUES ('bad','INTENT','{}','0','0')")
    os._exit(17)

def crashed_lock(lockfile):
    with advisory_lock(lockfile): os._exit(19)

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.j=Path(self.tmp.name)/'journal.sqlite'
    def test_legacy_verify_rejects_missing_journal(self):
        with self.assertRaises(ValueError): verify(self.j)
        self.assertFalse(self.j.exists())
    def test_missing_assess_does_not_create(self):
        with self.assertRaises(ValueError):assess(self.j)
        self.assertFalse(self.j.exists())
    def test_pending_manual(self):
        append(self.j,'restore-1','INTENT',{'destination':'/not/a/nas'})
        self.assertEqual(assess(self.j)['operations'][0]['status'],'MANUAL_REVIEW_REQUIRED')
    def test_published_closed(self):
        append(self.j,'a','INTENT');append(self.j,'a','PUBLISHED')
        self.assertEqual(assess(self.j)['operations'][0]['status'],'CLOSED_PUBLISHED')
    def test_failed_closed(self):
        append(self.j,'a','INTENT');append(self.j,'a','FAILED')
        self.assertEqual(assess(self.j)['operations'][0]['status'],'CLOSED_FAILED')
    def test_review_is_not_completion(self):
        append(self.j,'a','INTENT');append(self.j,'a','VERIFIED',{'reviewer':'human'})
        self.assertEqual(assess(self.j)['operations'][0]['status'],'MANUAL_REVIEW_REQUIRED')
    def test_invalid_transition(self):
        append(self.j,'a','PUBLISHED')
        with self.assertRaisesRegex(ValueError,'INVALID_TERMINAL_TRANSITION'):assess(self.j)
    def test_reused_operation(self):
        append(self.j,'a','INTENT');append(self.j,'a','FAILED');append(self.j,'a','INTENT')
        with self.assertRaisesRegex(ValueError,'OPERATION_REUSED'):assess(self.j)
    def test_crash_rolls_back_uncommitted_insert(self):
        append(self.j,'a','INTENT')
        p=multiprocessing.Process(target=crashed_writer,args=(str(self.j),));p.start();p.join(10)
        self.assertEqual(p.exitcode,17)
        self.assertEqual(verify(self.j)['events'],1)
        self.assertEqual(assess(self.j)['journal_events'],1)
    def test_crashed_process_releases_lock(self):
        append(self.j,'a','INTENT')
        p=multiprocessing.Process(target=crashed_lock,args=(str(self.j)+'.lock',));p.start();p.join(10)
        self.assertEqual(p.exitcode,19)
        self.assertEqual(assess(self.j)['journal_events'],1)
    def test_report_digest_and_safety(self):
        append(self.j,'a','INTENT')
        r=assess(self.j)
        self.assertEqual(len(r['sha256']),64)
        self.assertFalse(r['writes_to_nas']);self.assertFalse(r['cutover_authorized'])
    def test_chain_tamper(self):
        append(self.j,'a','INTENT')
        with sqlite3.connect(self.j) as c:c.execute("UPDATE restore_events SET phase='FAILED'")
        with self.assertRaisesRegex(ValueError,'JOURNAL_CORRUPT'):assess(self.j)

if __name__=='__main__':unittest.main()
