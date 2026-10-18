import unittest
from unittest.mock import patch, Mock
from ldaps_anchored_gate import AnchoredReviewGate, rotate_anchor_key, verify_anchored_startup
from ldaps_external_anchor import ExternalAnchorError

class TestAnchoredGate(unittest.TestCase):
    def setUp(self):
        self.rbac=Mock()
        self.key=b'a'*32
    @patch('ldaps_anchored_gate.ExternalPolicyAnchor')
    @patch('ldaps_anchored_gate.verify_startup')
    def test_startup_verifies_both(self, startup, anchor):
        result=verify_anchored_startup(self.rbac,now=5,anchor_path='/tmp/a',key=self.key)
        startup.assert_called_once_with(self.rbac,now=5,require_audited_policy=True)
        anchor.return_value.verify.assert_called_once_with()
        self.assertFalse(result['cutover_authorized'])
    @patch('ldaps_anchored_gate.ExternalPolicyAnchor')
    @patch('ldaps_anchored_gate.verify_startup')
    def test_missing_anchor_blocks(self,startup,anchor):
        anchor.return_value.verify.side_effect=ExternalAnchorError('MISSING')
        with self.assertRaises(ExternalAnchorError):
            verify_anchored_startup(self.rbac,now=5,anchor_path='/tmp/a',key=self.key)
    def test_facade_passes_anchor_inside_decision(self):
        gate=AnchoredReviewGate(self.rbac,anchor_path='/tmp/a',key=self.key)
        gate.decide('e','r',observation_hash='h',reviewer='s',action='BLOCK',decided_at=8)
        self.assertEqual(self.rbac.decide.call_args.kwargs['_external_anchor'],('/tmp/a',self.key))
    def test_facade_custom_age(self):
        gate=AnchoredReviewGate(self.rbac,anchor_path='/tmp/a',key=self.key)
        gate.decide('e','r',observation_hash='h',reviewer='s',action='BLOCK',decided_at=8,max_age_seconds=12)
        self.assertEqual(self.rbac.decide.call_args.kwargs['max_age_seconds'],12)
    def test_rotation_rejects_same_key(self):
        with self.assertRaises(ExternalAnchorError):
            rotate_anchor_key(self.rbac,now=8,anchor_path='/tmp/a',old_key=self.key,new_key=self.key)
    def test_rotation_rejects_short_key(self):
        with self.assertRaises(ExternalAnchorError):
            rotate_anchor_key(self.rbac,now=8,anchor_path='/tmp/a',old_key=self.key,new_key=b'x')
    @patch('ldaps_anchored_gate.ExternalPolicyAnchor')
    @patch('ldaps_anchored_gate.verify_anchored_startup')
    def test_rotation_requires_old_verification(self,verify,anchor):
        verify.side_effect=ExternalAnchorError('BAD_OLD')
        with self.assertRaises(ExternalAnchorError):
            rotate_anchor_key(self.rbac,now=8,anchor_path='/tmp/a',old_key=self.key,new_key=b'b'*32)
        anchor.assert_not_called()
    @patch('ldaps_anchored_gate.ExternalPolicyAnchor')
    @patch('ldaps_anchored_gate.verify_anchored_startup')
    def test_rotation_success(self,verify,anchor):
        anchor.return_value.checkpoint.return_value={'status':'EXTERNAL_ANCHOR_WRITTEN'}
        result=rotate_anchor_key(self.rbac,now=8,anchor_path='/tmp/a',old_key=self.key,new_key=b'b'*32)
        self.assertEqual(result['status'],'ANCHOR_KEY_ROTATED')
        self.assertFalse(result['execution_authorized'])
        verify.assert_called_once()

if __name__=='__main__': unittest.main()
