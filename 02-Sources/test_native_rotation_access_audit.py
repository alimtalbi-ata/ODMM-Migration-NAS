import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from native_rotation_access_audit import AccessAudit, make_denial_sink

class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'audit.db'
        self.key=b'a'*32
        self.audit=AccessAudit(self.path,key=self.key)
    def event(self, eid='e1', reason='DENIED'):
        return {'event_id':eid,'event':'rotation_access_denied','reason':reason}
    def test_append_verify(self):
        self.assertEqual(self.audit.append(self.event())['count'],1)
        self.assertEqual(self.audit.verify()['count'],1)
    def test_duplicate_idempotent(self):
        self.audit.append(self.event())
        self.assertTrue(self.audit.append(self.event())['duplicate'])
    def test_duplicate_conflict(self):
        self.audit.append(self.event())
        with self.assertRaisesRegex(ValueError,'DUPLICATE_CONFLICT'):
            self.audit.append(self.event(reason='OTHER'))
    def test_tamper_detected(self):
        self.audit.append(self.event())
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE access_audit SET payload='{}'")
        with self.assertRaises(ValueError):self.audit.verify()
    def test_missing_row_detected_by_head(self):
        self.audit.append(self.event())
        pinned=self.audit.verify()['head']
        with sqlite3.connect(self.path) as db:db.execute('DELETE FROM access_audit')
        with self.assertRaisesRegex(ValueError,'HEAD_MISMATCH'):
            AccessAudit(self.path,key=self.key,expected_head=pinned).verify(expected_head=pinned)
    def test_restart_with_anchor(self):
        self.audit.append(self.event())
        pinned=self.audit.verify()['head']
        restarted=AccessAudit(self.path,key=self.key,expected_head=pinned)
        self.assertEqual(restarted.append(self.event('e2'))['count'],2)
    def test_bad_key(self):
        with self.assertRaises(ValueError):AccessAudit(self.path,key=b'bad')
    def test_export(self):
        self.audit.append(self.event())
        export=self.audit.export_verified()
        self.assertEqual(export['events'][0]['event_id'],'e1')
    def test_denial_adapter(self):
        sink=make_denial_sink(self.audit,id_factory=lambda:'fixed')
        sink({'event':'rotation_access_denied','reason':'ROLE_DENIED'})
        self.assertEqual(self.audit.verify()['count'],1)
    def test_invalid_event(self):
        with self.assertRaises(ValueError):self.audit.append({'event_id':'x','event':'other'})
