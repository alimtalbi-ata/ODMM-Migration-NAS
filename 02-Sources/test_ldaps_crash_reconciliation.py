import sqlite3
import unittest
from ldaps_crash_reconciliation import CrashReconciliationLedger,CrashReconciliationError
from ldaps_durable_target import DurableFencedTarget

class C:
    def __init__(self,db):self.db=db

class Tests(unittest.TestCase):
    def setUp(self):
        self.a=sqlite3.connect(':memory:',isolation_level=None)
        self.b=sqlite3.connect(':memory:',isolation_level=None)
        self.target=DurableFencedTarget(self.b)
        self.target.advance_epoch('e',1)
        self.ledger=CrashReconciliationLedger(C(self.a),self.target)
    def tearDown(self):self.a.close();self.b.close()
    def effect(self):return self.target.apply(event_id='e',owner='w',epoch=1,operation='READ_ONLY',permit_hash='p',request_id='r')
    def test_missing_both(self):self.assertEqual(self.ledger.inspect('e','r')['state'],'NOT_APPLIED')
    def test_missing_receipt(self):
        self.effect();self.assertEqual(self.ledger.inspect('e','r')['state'],'TARGET_COMMITTED_RECEIPT_MISSING')
    def test_record(self):
        self.effect();self.assertEqual(self.ledger.record('e','r',observed_at=1)['status'],'RECONCILIATION_RECORDED')
    def test_chain(self):
        self.ledger.record('e','r',observed_at=1);self.ledger.record('e','r',observed_at=2);self.assertEqual(self.ledger.verify()['count'],2)
    def test_tamper(self):
        self.ledger.record('e','r',observed_at=1)
        self.a.execute("UPDATE ldaps_crash_reconciliations SET state='CONSISTENT'")
        with self.assertRaises(CrashReconciliationError):self.ledger.verify()
    def test_tamper_blocks_new(self):
        self.ledger.record('e','r',observed_at=1)
        self.a.execute("UPDATE ldaps_crash_reconciliations SET state='CONSISTENT'")
        with self.assertRaises(CrashReconciliationError):self.ledger.record('e','r',observed_at=2)
    def test_duplicate_time(self):
        self.ledger.record('e','r',observed_at=1)
        with self.assertRaises(sqlite3.IntegrityError):self.ledger.record('e','r',observed_at=1)
    def test_invalid_time(self):
        with self.assertRaises(CrashReconciliationError):self.ledger.record('e','r',observed_at=-1)
    def test_no_retry(self):self.assertFalse(self.ledger.record('e','r',observed_at=1)['automatic_retry'])
    def test_no_cutover(self):self.assertFalse(self.ledger.record('e','r',observed_at=1)['cutover_authorized'])
    def test_receipt_without_target(self):
        self.a.execute('CREATE TABLE ldaps_simulated_effect_receipts(event_id TEXT,request_id TEXT,target_hash TEXT)')
        self.a.execute("INSERT INTO ldaps_simulated_effect_receipts VALUES ('e','r','x')")
        self.assertEqual(self.ledger.inspect('e','r')['state'],'RECEIPT_WITHOUT_TARGET')
    def test_mismatch(self):
        self.effect()
        self.a.execute('CREATE TABLE ldaps_simulated_effect_receipts(event_id TEXT,request_id TEXT,target_hash TEXT)')
        self.a.execute("INSERT INTO ldaps_simulated_effect_receipts VALUES ('e','r','x')")
        self.assertEqual(self.ledger.inspect('e','r')['state'],'EVIDENCE_MISMATCH')
    def test_consistent(self):
        h=self.effect()['evidence_sha256']
        self.a.execute('CREATE TABLE ldaps_simulated_effect_receipts(event_id TEXT,request_id TEXT,target_hash TEXT)')
        self.a.execute('INSERT INTO ldaps_simulated_effect_receipts VALUES (?,?,?)',('e','r',h))
        self.assertEqual(self.ledger.inspect('e','r')['state'],'CONSISTENT')
    def test_target_tamper(self):
        self.effect();self.b.execute("UPDATE durable_target_effects SET evidence_hash='bad'")
        with self.assertRaises(Exception):self.ledger.record('e','r',observed_at=1)
    def test_audit_rollback_on_trigger(self):
        self.a.execute("CREATE TRIGGER deny_audit BEFORE INSERT ON ldaps_crash_reconciliations BEGIN SELECT RAISE(ABORT,'deny'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.ledger.record('e','r',observed_at=1)
        self.assertEqual(self.ledger.verify()['count'],0)
if __name__=='__main__':unittest.main()
