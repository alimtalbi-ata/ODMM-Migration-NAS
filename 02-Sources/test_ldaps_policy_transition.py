import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from ldaps_policy_transition import SupervisedPolicyTransition, PolicyTransitionError

class TestPolicyTransition(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.rbac=Mock()
        self.p=SupervisedPolicyTransition(self.rbac,anchor_path=Path(self.tmp.name)/'anchor',key=b'x'*32,intent_path=Path(self.tmp.name)/'intent')
    def test_initial_state(self):self.assertEqual(self.p.inspect()['status'],'NO_PENDING_TRANSITION')
    def test_paths_cannot_collide(self):
        with self.assertRaises(PolicyTransitionError):SupervisedPolicyTransition(self.rbac,anchor_path='x',key=b'x'*32,intent_path='x')
    def test_ack_requires_explicit_confirmation(self):
        with self.assertRaises(PolicyTransitionError):self.p.acknowledge(operator_confirmed=False)
    def test_ack_requires_verified_state(self):
        with self.assertRaises(PolicyTransitionError):self.p.acknowledge(operator_confirmed=True)
    def test_corrupt_intent_fails_closed(self):
        self.p.intent.write_text('{')
        with self.assertRaises(PolicyTransitionError):self.p.inspect()
    def test_incomplete_intent_fails_closed(self):
        self.p.intent.write_text('{}')
        with self.assertRaises(PolicyTransitionError):self.p.inspect()
    def test_intent_survives_restart(self):
        self.p._write({'version':1,'previous_head':'old','new_limit':100,'requested_at':3})
        other=SupervisedPolicyTransition(self.rbac,anchor_path=Path(self.tmp.name)/'anchor',key=b'x'*32,intent_path=self.p.intent)
        with patch('ldaps_policy_transition.AuditedFreshnessPolicy') as audit:
            audit.return_value.verify.return_value={'last_hash':'old'}
            self.assertEqual(other.inspect()['status'],'INTENT_ONLY_MANUAL_REVIEW')
    def test_pending_blocks_change(self):
        self.p._write({'version':1,'previous_head':'old','new_limit':100,'requested_at':3})
        with self.assertRaises(PolicyTransitionError):self.p.change(max_age_seconds=100,security_reviewer='a',operations_reviewer='b',now=4)
    @patch('ldaps_policy_transition.AuditedFreshnessPolicy')
    def test_failed_sqlite_keeps_intent(self,audit):
        audit.return_value.verify.return_value={'last_hash':'old'}
        audit.return_value.configure.side_effect=RuntimeError('disk')
        with patch.object(self.p.anchor,'verify'):
            with self.assertRaises(RuntimeError):self.p.change(max_age_seconds=100,security_reviewer='a',operations_reviewer='b',now=4)
        self.assertTrue(self.p.intent.exists())
    @patch('ldaps_policy_transition.AuditedFreshnessPolicy')
    def test_failed_anchor_keeps_intent(self,audit):
        audit.return_value.verify.return_value={'last_hash':'old'}
        audit.return_value.configure.return_value={'event_hash':'new'}
        with patch.object(self.p.anchor,'verify'),patch.object(self.p.anchor,'checkpoint',side_effect=OSError('disk')):
            with self.assertRaises(OSError):self.p.change(max_age_seconds=100,security_reviewer='a',operations_reviewer='b',now=4)
        self.assertTrue(self.p.intent.exists())
    @patch('ldaps_policy_transition.AuditedFreshnessPolicy')
    def test_success_still_requires_ack(self,audit):
        audit.return_value.verify.return_value={'last_hash':'old'}
        audit.return_value.configure.return_value={'event_hash':'new'}
        with patch.object(self.p.anchor,'verify'),patch.object(self.p.anchor,'checkpoint'):
            self.assertEqual(self.p.change(max_age_seconds=100,security_reviewer='a',operations_reviewer='b',now=4)['status'],'POLICY_PUBLISHED_PENDING_ACK')
        self.assertTrue(self.p.intent.exists())
    @patch('ldaps_policy_transition.AuditedFreshnessPolicy')
    def test_anchor_uncertain(self,audit):
        self.p._write({'version':1,'previous_head':'old','new_limit':100,'requested_at':3})
        audit.return_value.verify.return_value={'last_hash':'new'}
        self.rbac.db.execute.return_value.fetchone.return_value=(100,)
        with patch.object(self.p.anchor,'verify',side_effect=Exception('invalid')):
            # ExternalAnchorError is required for known verification failures.
            pass
        from ldaps_external_anchor import ExternalAnchorError
        with patch.object(self.p.anchor,'verify',side_effect=ExternalAnchorError('invalid')):
            self.assertEqual(self.p.inspect()['status'],'SQLITE_COMMITTED_ANCHOR_UNCERTAIN')
    @patch('ldaps_policy_transition.AuditedFreshnessPolicy')
    def test_verified_ack_removes_intent(self,audit):
        self.p._write({'version':1,'previous_head':'old','new_limit':100,'requested_at':3})
        audit.return_value.verify.return_value={'last_hash':'new'}
        self.rbac.db.execute.return_value.fetchone.return_value=(100,)
        with patch.object(self.p.anchor,'verify'):
            self.assertEqual(self.p.acknowledge(operator_confirmed=True)['status'],'TRANSITION_ACKNOWLEDGED')
        self.assertFalse(self.p.intent.exists())
if __name__=='__main__':unittest.main()
