import tempfile
import unittest
from pathlib import Path
from review_event_journal import ReviewEventJournal, JournalError

H = 'a'*64
class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/'events.db'
        self.j = ReviewEventJournal(self.path)
    def tearDown(self):
        self.j.close()
        self.temp.cleanup()
    def add(self, action='REVIEW_RECORDED', actor='alice'):
        return self.j.append('migration-1',action,actor,H,now=100)
    def test_empty(self):
        self.assertEqual(self.j.verify()['events'],0)
    def test_one(self):
        self.assertEqual(self.add()['cutover_authorized'],False)
        self.assertEqual(self.j.verify()['status'],'CHAIN_INTACT_UNAUTHENTICATED')
    def test_two(self):
        self.add();self.add('REVIEW_REVOKED','bob')
        self.assertEqual(self.j.verify()['events'],2)
    def test_restart(self):
        self.add();self.j.close();self.j=ReviewEventJournal(self.path)
        self.assertEqual(self.j.verify()['events'],1)
    def test_payload_tamper(self):
        self.add();self.j.db.execute("UPDATE review_events SET event_json='{}' WHERE seq=1")
        self.assertEqual(self.j.verify()['status'],'TAMPER_DETECTED')
    def test_hash_tamper(self):
        self.add();self.j.db.execute("UPDATE review_events SET entry_hash=? WHERE seq=1",('b'*64,))
        self.assertEqual(self.j.verify()['status'],'TAMPER_DETECTED')
    def test_delete_gap(self):
        self.add();self.add('REVIEW_REVOKED','bob');self.j.db.execute('DELETE FROM review_events WHERE seq=1')
        self.assertEqual(self.j.verify()['status'],'TAMPER_DETECTED')
    def test_bad_action(self):
        with self.assertRaises(JournalError):self.add('CUTOVER_AUTHORIZED')
    def test_bad_hash(self):
        with self.assertRaises(JournalError):self.j.append('m','REVIEW_RECORDED','a','xyz')
    def test_bad_actor(self):
        with self.assertRaises(JournalError):self.j.append('m','REVIEW_RECORDED','',H)
    def test_bad_time(self):
        with self.assertRaises(JournalError):self.j.append('m','REVIEW_RECORDED','a',H,now=-1)
    def test_concurrent_writers(self):
        self.add()
        with ReviewEventJournal(self.path) as second:
            second.append('migration-1','REVIEW_RECORDED','bob',H,now=101)
        self.assertEqual(self.j.verify()['events'],2)
