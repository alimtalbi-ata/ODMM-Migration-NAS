import copy
import unittest
from test_privilege_evidence_gate import GateTests
from test_migration_acl_risk_report import item, S
from migration_acl_risk_report import assess_migration_acl_risk
from privilege_evidence_gate import assess_privilege_evidence
from cutover_readiness_gate import assess_cutover_readiness, verify_cutover_readiness, CutoverGateError

class CutoverReadinessTests(unittest.TestCase):
    def setUp(self):
        self.fixture = GateTests(); self.fixture.setUp()
        self.datasets = [item()]
        self.recovery = {'status':'PASS_DECLARED','evidence_ref':'operator-run-001'}
    def args(self):
        inputs = self.fixture.args()
        return ('migration', self.datasets, assess_migration_acl_risk('migration',self.datasets),
                assess_privilege_evidence(*inputs), inputs, self.recovery)
    def test_matching_evidence_still_requires_human(self):
        r=assess_cutover_readiness(*self.args())['report']
        self.assertEqual(r['status'],'PENDING_HUMAN_AND_LIVE_VERIFICATION')
        self.assertFalse(r['cutover_authorized'])
    def test_acl_drift_blocks(self):
        self.datasets=[item(target=S.replace('0x3/','0x2/'))]
        self.assertEqual(assess_cutover_readiness(*self.args())['report']['status'],'BLOCKED')
    def test_privilege_drift_blocks(self):
        self.fixture.right[0]['decision']='DENY'
        self.assertEqual(assess_cutover_readiness(*self.args())['report']['status'],'BLOCKED')
    def test_recovery_failure_blocks(self):
        self.recovery['status']='FAIL_DECLARED'
        self.assertEqual(assess_cutover_readiness(*self.args())['report']['status'],'BLOCKED')
    def test_recovery_not_tested_indeterminate(self):
        self.recovery['status']='NOT_TESTED'
        self.assertEqual(assess_cutover_readiness(*self.args())['report']['status'],'INDETERMINATE')
    def test_bad_recovery_rejected(self):
        self.recovery['status']='CERTIFIED'
        with self.assertRaises(CutoverGateError):assess_cutover_readiness(*self.args())
    def test_tampered_acl_rejected(self):
        a=list(self.args());a[2]['sha256']='0'*64
        with self.assertRaises(CutoverGateError):assess_cutover_readiness(*a)
    def test_tampered_privilege_rejected(self):
        a=list(self.args());a[3]['report']['cutover_authorized']=True
        with self.assertRaises(CutoverGateError):assess_cutover_readiness(*a)
    def test_deterministic(self):
        self.assertEqual(assess_cutover_readiness(*self.args()),assess_cutover_readiness(*self.args()))
    def test_report_tamper_rejected(self):
        a=self.args(); b=assess_cutover_readiness(*a)
        self.assertTrue(verify_cutover_readiness(b,*a))
        b['report']['cutover_authorized']=True
        with self.assertRaises(CutoverGateError):verify_cutover_readiness(b,*a)
    def test_no_raw_acl(self):
        self.assertNotIn('OWNER:S-1-5-21-100',str(assess_cutover_readiness(*self.args())))
    def test_invalid_inputs(self):
        a=list(self.args());a[4]=[]
        with self.assertRaises(CutoverGateError):assess_cutover_readiness(*a)
