"""V203.8 read-only journal regression tests. Author: Abdelhalim Talbi."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_restore_journal_v2034 import append, verify, digest

class JournalHardening(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p=Path(self.tmp.name)/'journal.sqlite'
    def test_missing_no_create(self):
        with self.assertRaisesRegex(ValueError,'JOURNAL_MISSING'):
            verify(self.p)
        self.assertFalse(self.p.exists())
    def test_valid_pending(self):
        append(self.p,'run','INTENT',{'destination':'x'})
        self.assertEqual(verify(self.p)['pending_operations'],['run'])
    def test_valid_published(self):
        append(self.p,'run','INTENT')
        append(self.p,'run','PUBLISHED')
        self.assertEqual(verify(self.p)['pending_operations'],[])
    def test_valid_review(self):
        append(self.p,'run','INTENT')
        append(self.p,'run','VERIFIED')
        self.assertTrue(verify(self.p)['valid'])
    def test_symlink_rejected(self):
        append(self.p,'run','INTENT')
        link=self.p.with_name('link.sqlite'); link.symlink_to(self.p)
        with self.assertRaises(ValueError): verify(link)
    def test_no_modify_db(self):
        append(self.p,'run','INTENT')
        before=self.p.read_bytes()
        verify(self.p)
        self.assertEqual(before,self.p.read_bytes())
    def test_tamper_detected(self):
        append(self.p,'run','INTENT')
        with sqlite3.connect(self.p) as db: db.execute("UPDATE restore_events SET payload='\"altered\"' WHERE seq=1")
        self.assertFalse(verify(self.p)['valid'])
    def test_invalid_json_even_if_chain_rehashed(self):
        append(self.p,'run','INTENT')
        with sqlite3.connect(self.p) as db:
            row=db.execute('SELECT seq,operation,phase,prev_hash FROM restore_events').fetchone()
            seq,op,phase,prev=row
            payload='not json'
            h=digest({'seq':seq,'operation':op,'phase':phase,'payload':payload,'prev_hash':prev})
            db.execute('UPDATE restore_events SET payload=?,event_hash=?',(payload,h))
        self.assertFalse(verify(self.p)['valid'])
    def test_duplicate_intent_rejected(self):
        append(self.p,'run','INTENT'); append(self.p,'run','INTENT')
        self.assertTrue(verify(self.p)['valid'])
    def test_terminal_without_intent_rejected(self):
        append(self.p,'run','PUBLISHED')
        self.assertFalse(verify(self.p)['valid'])
    def test_unrelated_files_untouched(self):
        marker=self.p.with_name('important'); marker.write_text('keep')
        with self.assertRaises(ValueError): verify(self.p)
        self.assertEqual(marker.read_text(),'keep')

if __name__=='__main__': unittest.main()
