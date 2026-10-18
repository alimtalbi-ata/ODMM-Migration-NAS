import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from native_audit_export import (build_bundle, verify_bundle, checkpoint,
    rotation_attestation, verify_rotation_attestation, export_file)
from native_orphan_audit import append
from native_migration_errors import MigrationBlocked
A=b'A'*32
B=b'B'*32

class AuditExportV1908Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.tmp.name)/'audit.sqlite')
        self.db=sqlite3.connect(self.path,isolation_level=None,timeout=5)
        self.db.execute('PRAGMA journal_mode=WAL')
    def tearDown(self):
        self.db.close();self.tmp.cleanup()
    def add(self,db=None):
        append(db or self.db,A,kind='REVIEW',review_id='x',path='a',operator='ops',rationale='manual review')
    def test_concurrent_writer_snapshot(self):
        self.add()
        other=sqlite3.connect(self.path,isolation_level=None,timeout=5,check_same_thread=False)
        ready=threading.Event();done=threading.Event()
        def writer():
            ready.wait(2)
            self.add(other)
            done.set()
        t=threading.Thread(target=writer);t.start()
        self.db.execute('BEGIN')
        try:
            self.db.execute('SELECT COUNT(*) FROM orphan_audit_chain').fetchone()
            ready.set();self.assertTrue(done.wait(3))
            bundle=build_bundle(self.db,A)
            self.assertEqual(verify_bundle(bundle,A)['events'],1)
        finally:
            self.db.execute('ROLLBACK');t.join(3);other.close()
        self.assertEqual(verify_bundle(build_bundle(self.db,A),A)['events'],2)
    def test_export_after_concurrent_append(self):
        self.add()
        out=Path(self.tmp.name)/'evidence.json'
        export_file(self.db,A,out)
        self.assertEqual(verify_bundle(json.loads(out.read_text()),A)['events'],1)
    def test_rotation_dual_signature(self):
        self.add();cp=checkpoint(build_bundle(self.db,A),A)
        proof=rotation_attestation(cp,A,B,old_key_id='2026-A',new_key_id='2026-B')
        self.assertEqual(verify_rotation_attestation(proof,A,B)['status'],'DUAL_SIGNATURE_VERIFIED')
    def test_rotation_wrong_new_key(self):
        cp=checkpoint(build_bundle(self.db,A),A)
        proof=rotation_attestation(cp,A,B,old_key_id='a',new_key_id='b')
        with self.assertRaises(MigrationBlocked):verify_rotation_attestation(proof,A,b'C'*32)
    def test_rotation_tamper(self):
        cp=checkpoint(build_bundle(self.db,A),A)
        proof=rotation_attestation(cp,A,B,old_key_id='a',new_key_id='b')
        proof['payload']['new_key_id']='other'
        with self.assertRaises(MigrationBlocked):verify_rotation_attestation(proof,A,B)
    def test_rotation_same_key_rejected(self):
        cp=checkpoint(build_bundle(self.db,A),A)
        with self.assertRaises(MigrationBlocked):rotation_attestation(cp,A,A,old_key_id='a',new_key_id='b')
    def test_rotation_same_key_id_rejected(self):
        cp=checkpoint(build_bundle(self.db,A),A)
        with self.assertRaises(MigrationBlocked):rotation_attestation(cp,A,B,old_key_id='a',new_key_id='a')
    def test_rotation_does_not_apply(self):
        cp=checkpoint(build_bundle(self.db,A),A)
        proof=rotation_attestation(cp,A,B,old_key_id='a',new_key_id='b')
        self.assertFalse(proof['rotation_applied'])
        self.assertEqual(verify_bundle(build_bundle(self.db,A),A)['events'],0)
