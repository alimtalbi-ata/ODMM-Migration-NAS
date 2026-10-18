import sqlite3
import unittest
from ldaps_identity_revocation import IdentityRevocationRegistry
from ldaps_transition_reconciliation import TransitionReconciliationError

class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        self.registry=IdentityRevocationRegistry(self.db)
    def tearDown(self): self.db.close()
    def test_empty(self): self.assertEqual(self.registry.verify(),[])
    def test_revoke_issuer(self):
        self.registry.revoke(kind='issuer',identifier='issuer1',now=10)
        with self.assertRaisesRegex(TransitionReconciliationError,'IDENTITY_REVOKED'):
            self.registry.assert_active(issuer='issuer1',subject='a',token_id='b')
    def test_revoke_subject(self):
        self.registry.revoke(kind='subject',identifier='alice',now=10)
        with self.assertRaisesRegex(TransitionReconciliationError,'IDENTITY_REVOKED'):
            self.registry.assert_active(issuer='i',subject='alice',token_id='t')
    def test_revoke_token(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        with self.assertRaisesRegex(TransitionReconciliationError,'IDENTITY_REVOKED'):
            self.registry.assert_active(issuer='i',subject='a',token_id='t')
    def test_other_identity_allowed(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        self.assertTrue(self.registry.assert_active(issuer='i',subject='a',token_id='other'))
    def test_duplicate_rejected(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        with self.assertRaisesRegex(TransitionReconciliationError,'REVOCATION_ALREADY_RECORDED'):
            self.registry.revoke(kind='token',identifier='t',now=11)
    def test_time_regression(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        with self.assertRaisesRegex(TransitionReconciliationError,'REVOCATION_TIME_REGRESSION'):
            self.registry.revoke(kind='token',identifier='u',now=9)
    def test_invalid_kind(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'INVALID_REVOCATION'):
            self.registry.revoke(kind='role',identifier='x',now=10)
    def test_bool_time_invalid(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'INVALID_REVOCATION'):
            self.registry.revoke(kind='token',identifier='x',now=True)
    def test_tamper_detected(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        self.db.execute("UPDATE identity_revocations SET identifier='evil'")
        with self.assertRaisesRegex(TransitionReconciliationError,'IDENTITY_REVOCATION_AUDIT_TAMPERED'):
            self.registry.verify()
    def test_persistent_reopen(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        other=IdentityRevocationRegistry(self.db)
        self.assertEqual(len(other.verify()),1)
    def test_rollback_trigger(self):
        self.db.execute("CREATE TRIGGER block_revoke BEFORE INSERT ON identity_revocations BEGIN SELECT RAISE(ABORT,'blocked'); END")
        with self.assertRaises(sqlite3.DatabaseError):
            self.registry.revoke(kind='token',identifier='t',now=10)
        self.assertEqual(self.registry.verify(),[])
    def test_audit_chain(self):
        self.registry.revoke(kind='token',identifier='t',now=10)
        self.registry.revoke(kind='subject',identifier='a',now=11)
        self.assertEqual(len(self.registry.verify()),2)

if __name__=='__main__': unittest.main()
