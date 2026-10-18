import os
import unittest
from native_orphan_review import create_review, approve_for_manual_investigation
from native_posix_migration import MigrationBlocked
from test_native_posix_migration import NativeMigrationTests

class OrphanReviewTests(unittest.TestCase):
    setUp=NativeMigrationTests.setUp
    engine=NativeMigrationTests.engine
    def candidate(self):
        name='.odmm-'+'a'*32+'.part'
        (self.dst/name).write_bytes(b'temp')
        return name
    def test_empty(self):
        with self.engine() as e: self.assertEqual(create_review(e), [])
    def test_review_persists_restart_and_no_delete(self):
        name=self.candidate()
        with self.engine() as e: rid=create_review(e)[0]['review_id']
        with self.engine() as e:
            out=approve_for_manual_investigation(e,rid,operator='tester',rationale='Manual investigation planned',audit_key=b'K'*32)
            self.assertFalse(out['auto_delete_authorized'])
        self.assertTrue((self.dst/name).exists())
    def test_no_operator(self):
        self.candidate()
        with self.engine() as e:
            rid=create_review(e)[0]['review_id']
            with self.assertRaises(MigrationBlocked): approve_for_manual_investigation(e,rid,operator='',rationale='Valid long reason',audit_key=b'K'*32)
    def test_no_double_approval(self):
        self.candidate()
        with self.engine() as e:
            rid=create_review(e)[0]['review_id']
            approve_for_manual_investigation(e,rid,operator='op',rationale='Manual investigation planned',audit_key=b'K'*32)
            with self.assertRaises(MigrationBlocked): approve_for_manual_investigation(e,rid,operator='op',rationale='Manual investigation planned',audit_key=b'K'*32)
    def test_changed_content_rejected(self):
        name=self.candidate()
        with self.engine() as e:
            rid=create_review(e)[0]['review_id']
            (self.dst/name).write_bytes(b'changed')
            with self.assertRaises(MigrationBlocked): approve_for_manual_investigation(e,rid,operator='op',rationale='Manual investigation planned',audit_key=b'K'*32)
    def test_replaced_inode_rejected(self):
        name=self.candidate()
        with self.engine() as e:
            rid=create_review(e)[0]['review_id']
            os.unlink(self.dst/name); (self.dst/name).write_bytes(b'temp')
            with self.assertRaises(MigrationBlocked): approve_for_manual_investigation(e,rid,operator='op',rationale='Manual investigation planned',audit_key=b'K'*32)
    def test_pending_intent_blocks(self):
        self.candidate()
        with self.engine() as e:
            rid=create_review(e)[0]['review_id']
            e.db.execute('INSERT INTO intents VALUES (?,?,?,?,?)',('a',1,'a'*64,0o600,0))
            with self.assertRaises(MigrationBlocked): approve_for_manual_investigation(e,rid,operator='op',rationale='Manual investigation planned',audit_key=b'K'*32)
    def test_missing_rejected(self):
        name=self.candidate()
        with self.engine() as e:
            rid=create_review(e)[0]['review_id']
            (self.dst/name).unlink()
            with self.assertRaises(MigrationBlocked): approve_for_manual_investigation(e,rid,operator='op',rationale='Manual investigation planned',audit_key=b'K'*32)
