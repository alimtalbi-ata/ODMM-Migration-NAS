import tempfile
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch, verify_epochs
from native_cockpit_review_decisions import sign_review, record_review, verify_reviews
from native_rotation_target_binding import sign_target_approval
from native_rotation_unified_gate import rotate_with_unified_governance
from native_rotation_revocation_chain import initialize_revocations

class UnifiedGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'journal.db';self.keys={'old':b'a'*32,'new':b'b'*32};self.gateway=b'g'*32;self.ledger=b'l'*32
        start=transact_epoch(self.db,keys=self.keys,operation='START',key_id='old')
        self.head=start['head'];self.now=100000000000
        self.review=sign_review(gateway_key=self.gateway,request_id='request-001',requester='alice',reviewer='bob',decision='APPROVE',expected_head=self.head,issued_ns=self.now-10,expires_ns=self.now+100)
        record_review(self.db,keys=self.keys,signed=self.review,gateway_key=self.gateway,ledger_key=self.ledger,now_ns=self.now)
        self.anchor=verify_reviews(self.db,ledger_key=self.ledger)['head']
        self.revocation_key=b'r'*32; self.revocation_head=initialize_revocations(self.db,revocation_key=self.revocation_key)['head']
        self.target=sign_target_approval(gateway_key=self.gateway,request_id='request-001',requester='alice',reviewer='bob',target_key_id='new',expected_head=self.head,issued_ns=self.now-10,expires_ns=self.now+100)
    def call(self,**kwargs):
        args=dict(keys=self.keys,request_id='request-001',target_key_id='new',signed_target=self.target,gateway_key=self.gateway,ledger_key=self.ledger,trusted_review_head=self.anchor,now_ns=self.now,revocation_key=self.revocation_key,trusted_revocation_head=self.revocation_head)
        args.update(kwargs);return rotate_with_unified_governance(self.db,**args)
    def test_success(self):self.assertTrue(self.call()['rotation_applied'])
    def test_replay(self):
        self.call()
        with self.assertRaises(ValueError):self.call()
    def test_missing_external_anchor(self):
        with self.assertRaisesRegex(ValueError,'EXTERNAL_REVIEW_ANCHOR_REQUIRED'):self.call(trusted_review_head=None)
    def test_wrong_external_anchor(self):
        with self.assertRaisesRegex(ValueError,'REVIEW_ANCHOR_MISMATCH'):self.call(trusted_review_head='f'*64)
    def test_target_mismatch(self):
        with self.assertRaisesRegex(ValueError,'TARGET_APPROVAL_MISMATCH'):self.call(target_key_id='old')
    def test_forged_target(self):
        fake={'payload':dict(self.target['payload']),'gateway_mac':self.target['gateway_mac']};fake['payload']['reviewer']='eve'
        with self.assertRaisesRegex(ValueError,'APPROVAL_MAC_INVALID'):self.call(signed_target=fake)
    def test_stale_head(self):
        transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='0'*64)
        with self.assertRaisesRegex(ValueError,'APPROVAL_STALE_HEAD'):self.call()
    def test_expired(self):
        with self.assertRaises(ValueError):self.call(now_ns=self.now+101)
    def test_revoked(self):
        import sqlite3
        with sqlite3.connect(self.db) as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS epoch_review_revocations(request_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, gateway_mac TEXT NOT NULL, recorded_ns INTEGER NOT NULL)')
            conn.execute('INSERT INTO epoch_review_revocations VALUES (?,?,?,?)',('request-001','{}','0'*64,self.now))
        with self.assertRaisesRegex(ValueError,'REVIEW_REVOKED'):self.call()
    def test_no_mutation_on_failure(self):
        before=verify_epochs(self.db,keys=self.keys)['head']
        with self.assertRaises(ValueError):self.call(trusted_review_head='0'*64)
        self.assertEqual(before,verify_epochs(self.db,keys=self.keys)['head'])

if __name__=='__main__':unittest.main()

class RevocationFailClosedTests(UnifiedGateTests):
    def test_missing_revocation_ledger_blocks_rotation(self):
        import sqlite3
        with sqlite3.connect(self.db) as conn:
            conn.execute('DROP TABLE epoch_review_revocations')
        before = verify_epochs(self.db, keys=self.keys)['head']
        with self.assertRaisesRegex(ValueError, 'REVOCATION_LEDGER_MISSING'):
            self.call()
        self.assertEqual(before, verify_epochs(self.db, keys=self.keys)['head'])

    def test_review_initializes_revocation_ledger(self):
        import sqlite3
        with sqlite3.connect(self.db) as conn:
            self.assertIsNotNone(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='epoch_review_revocations'").fetchone())
