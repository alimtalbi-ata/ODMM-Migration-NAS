import unittest
from ldaps_witness_recovery_gate import WitnessRecoveryGate
from ldaps_ipc_persistent_identity import IdentityPinError

HEAD='a'*64
class Anchor:
    def __init__(self): self.count=2;self.head=HEAD;self.bad=False
    def verify(self):
        if self.bad: raise IdentityPinError('REVIEW_ANCHOR_LEDGER_MISMATCH')
        return {'status':'REVIEW_ANCHOR_VERIFIED','count':self.count}
    def _read(self): return {'count':self.count,'last_mac':self.head}
class Remote:
    def __init__(self): self.fail=None;self.calls=0
    def verify(self,*,expected_count,expected_last_mac):
        self.calls+=1
        if self.fail: raise IdentityPinError(self.fail)
        return {'status':'REMOTE_WITNESS_VERIFIED','count':expected_count}
class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.anchor=Anchor();self.remote=Remote()
        self.gate=WitnessRecoveryGate(verifier=self.remote,local_anchor=self.anchor,clock=lambda:123)
        self.args=dict(expected_count=2,expected_last_mac=HEAD,incident_id='RESTORE-001',operator_acknowledged=True)
    def test_success_non_authorizing(self):
        r=self.gate.assess(**self.args)
        self.assertEqual(r['status'],'WITNESS_RECOVERY_EVIDENCE_MATCH')
        self.assertFalse(r['recovery_authorized']);self.assertFalse(r['cutover_authorized'])
        self.assertEqual(r['checked_at_unix'],123)
    def test_confirmation_required(self):
        with self.assertRaisesRegex(IdentityPinError,'ACK_REQUIRED'):
            self.gate.assess(**{**self.args,'operator_acknowledged':False})
        self.assertEqual(self.remote.calls,0)
    def test_local_rollback(self):
        self.anchor.count=1
        with self.assertRaisesRegex(IdentityPinError,'LOCAL_STATE_CHANGED'):self.gate.assess(**self.args)
    def test_local_tamper(self):
        self.anchor.bad=True
        with self.assertRaisesRegex(IdentityPinError,'ANCHOR_LEDGER_MISMATCH'):self.gate.assess(**self.args)
    def test_remote_divergence(self):
        self.remote.fail='REMOTE_WITNESS_DIVERGENCE_MANUAL_REVIEW'
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):self.gate.assess(**self.args)
    def test_network_outage(self):
        self.remote.fail='REMOTE_WITNESS_UNAVAILABLE'
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):self.gate.assess(**self.args)
    def test_bad_incident(self):
        with self.assertRaisesRegex(IdentityPinError,'INPUT_INVALID'):self.gate.assess(**{**self.args,'incident_id':'x\n'})
    def test_wrong_head(self):
        with self.assertRaisesRegex(IdentityPinError,'LOCAL_STATE_CHANGED'):self.gate.assess(**{**self.args,'expected_last_mac':'b'*64})
    def test_no_retry_on_divergence(self):
        self.remote.fail='REMOTE_WITNESS_DIVERGENCE_MANUAL_REVIEW'
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):self.gate.retry_assess(attempts=3,**self.args)
        self.assertEqual(self.remote.calls,1)
    def test_bounded_retry(self):
        self.remote.fail='REMOTE_WITNESS_UNAVAILABLE'
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):self.gate.retry_assess(attempts=3,**self.args)
        self.assertEqual(self.remote.calls,3)
    def test_retry_recovery(self):
        original=self.remote.verify
        def flaky(**kw):
            if self.remote.calls==0:
                self.remote.calls+=1;raise IdentityPinError('REMOTE_WITNESS_UNAVAILABLE')
            return original(**kw)
        self.remote.verify=flaky
        self.assertEqual(self.gate.retry_assess(attempts=2,**self.args)['count'],2)
    def test_retry_limit(self):
        with self.assertRaisesRegex(IdentityPinError,'RETRY_INVALID'):self.gate.retry_assess(attempts=0,**self.args)
if __name__=='__main__':unittest.main()
