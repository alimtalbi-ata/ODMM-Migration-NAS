import sqlite3
import unittest
from native_migration_errors import MigrationBlocked
from native_orphan_audit import append, verify
from native_orphan_review import create_review, approve_for_manual_investigation
from test_native_posix_migration import NativeMigrationTests

KEY=b'A'*32
class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:', isolation_level=None)
    def tearDown(self):
        self.db.close()
    def add(self):
        return append(self.db, KEY,kind='REVIEW',review_id='r',path='.odmm-test.part',operator='op',rationale='Manual inspection')
    def test_chain(self):
        self.add(); self.add(); self.assertEqual(verify(self.db,KEY)['events'],2)
    def test_wrong_key(self):
        self.add()
        with self.assertRaises(MigrationBlocked): verify(self.db,b'B'*32)
    def test_mutated_event(self):
        self.add(); self.db.execute("UPDATE orphan_audit_chain SET event_json='{}' WHERE seq=1")
        with self.assertRaises(MigrationBlocked): verify(self.db,KEY)
    def test_deleted_middle(self):
        self.add();self.add();self.db.execute('DELETE FROM orphan_audit_chain WHERE seq=1')
        with self.assertRaises(MigrationBlocked): verify(self.db,KEY)
    def test_weak_key(self):
        with self.assertRaises(MigrationBlocked): self.add_weak()
    def add_weak(self):
        append(self.db,b'weak',kind='REVIEW',review_id='r',path='p',operator='o',rationale='r')
    def test_approval_atomic_evidence(self):
        t=NativeMigrationTests('test_copy_and_verify'); t.setUp()
        try:
            name='.odmm-'+'a'*32+'.part'; (t.dst/name).write_bytes(b'temp')
            with t.engine() as e:
                rid=create_review(e)[0]['review_id']
                out=approve_for_manual_investigation(e,rid,operator='operator',rationale='Investigate orphan safely',audit_key=KEY)
                self.assertEqual(out['audit']['sequence'],1)
                self.assertEqual(verify(e.db,KEY)['events'],1)
                self.assertTrue((t.dst/name).exists())
        finally: t.tearDown()
    def test_approval_wrong_key_rolls_back(self):
        t=NativeMigrationTests('test_copy_and_verify'); t.setUp()
        try:
            name='.odmm-'+'a'*32+'.part'; (t.dst/name).write_bytes(b'temp')
            with t.engine() as e:
                rid=create_review(e)[0]['review_id']
                approve_for_manual_investigation(e,rid,operator='operator',rationale='Investigate orphan safely',audit_key=KEY)
                e.db.execute('UPDATE orphan_reviews SET state=? WHERE review_id=?',('PENDING',rid))
                with self.assertRaises(MigrationBlocked):
                    approve_for_manual_investigation(e,rid,operator='operator',rationale='Investigate orphan safely',audit_key=b'B'*32)
                self.assertEqual(e.db.execute('SELECT state FROM orphan_reviews WHERE review_id=?',(rid,)).fetchone()[0],'PENDING')
        finally: t.tearDown()
