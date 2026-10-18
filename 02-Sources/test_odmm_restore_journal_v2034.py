import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_restore_journal_v2034 import append,verify,advisory_lock

def worker(db,ident):
    for i in range(6): append(db,ident,'INTENT',{'i':i})

def crash_worker(lock):
    with advisory_lock(lock): os._exit(7)

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=str(Path(self.temp.name)/'audit.sqlite')
    def test_empty(self):
        with self.assertRaises(ValueError): verify(self.db)
        self.assertFalse(Path(self.db).exists())
    def test_chain(self):
        append(self.db,'a','INTENT');append(self.db,'a','PUBLISHED');self.assertEqual(verify(self.db)['pending_operations'],[])
    def test_pending(self):
        append(self.db,'a','INTENT');self.assertEqual(verify(self.db)['pending_operations'],['a'])
    def test_failed(self):
        append(self.db,'a','INTENT');append(self.db,'a','FAILED');self.assertFalse(verify(self.db)['pending_operations'])
    def test_tamper(self):
        append(self.db,'a','INTENT')
        with sqlite3.connect(self.db) as c: c.execute("UPDATE restore_events SET phase='PUBLISHED'")
        self.assertFalse(verify(self.db)['valid'])
    def test_gap(self):
        append(self.db,'a','INTENT');append(self.db,'b','INTENT')
        with sqlite3.connect(self.db) as c:c.execute('DELETE FROM restore_events WHERE seq=1')
        self.assertFalse(verify(self.db)['valid'])
    def test_invalid_phase(self):
        with self.assertRaises(ValueError):append(self.db,'a','UNKNOWN')
    def test_concurrent_processes(self):
        ps=[multiprocessing.Process(target=worker,args=(self.db,str(i))) for i in range(3)]
        for p in ps:p.start()
        for p in ps:p.join(15);self.assertEqual(p.exitcode,0)
        self.assertEqual(verify(self.db)['events'],18)
    @unittest.skipIf(os.name=='nt','POSIX forced exit test')
    def test_lock_released_on_crash(self):
        lock=str(Path(self.temp.name)/'lock')
        p=multiprocessing.Process(target=crash_worker,args=(lock,));p.start();p.join(10)
        self.assertEqual(p.exitcode,7)
        with advisory_lock(lock): pass
    def test_no_nas_writes(self):
        append(self.db,'a','INTENT');self.assertFalse(verify(self.db)['writes_to_nas'])

if __name__=='__main__':unittest.main()
