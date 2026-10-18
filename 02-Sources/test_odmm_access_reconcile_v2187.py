import copy, tempfile, unittest
from pathlib import Path
from odmm_access_audit_v2184 import AuditError,digest
from odmm_access_anchor_v2185 import verify_anchored
from odmm_access_reconcile_v2187 import reconcile_campaign,reconcile_and_audit

def fixture(equal=True):
    r={'case_id':'nas-pair-01','execution_euid':1001,'execution_egid':1001,'local_open_outcomes_equal':equal,'cutover_authorized':False}
    report={'schema':'odmm.isolated-access-campaign.v2183','cases':[{'report':r,'sha256':digest(r)}], 'execution_euid':1001,'execution_egid':1001,'all_local_outcomes_equal':equal,'nas_qualified':False,'cutover_authorized':False,'dedicated_account_attested':False}
    return {'report':report,'sha256':digest(report)}

class ReconcileTests(unittest.TestCase):
    def test_match(self):
        r=reconcile_campaign(fixture());self.assertTrue(r['report']['all_local_outcomes_equal']);self.assertFalse(r['report']['cutover_authorized'])
    def test_mismatch_is_evidence_not_approval(self):
        r=reconcile_campaign(fixture(False));self.assertFalse(r['report']['all_local_outcomes_equal'])
    def test_tampered_case(self):
        c=fixture();c['report']['cases'][0]['report']['case_id']='changed';c['sha256']=digest(c['report'])
        with self.assertRaisesRegex(AuditError,'CASE_EVIDENCE'):reconcile_campaign(c)
    def test_duplicate_case(self):
        c=fixture();c['report']['cases']*=2;c['sha256']=digest(c['report'])
        with self.assertRaisesRegex(AuditError,'DUPLICATE'):reconcile_campaign(c)
    def test_identity_mismatch(self):
        c=fixture();r=c['report']['cases'][0]['report'];r['execution_euid']=999;c['report']['cases'][0]['sha256']=digest(r);c['sha256']=digest(c['report'])
        with self.assertRaisesRegex(AuditError,'IDENTITY_MISMATCH'):reconcile_campaign(c)
    def test_summary_forgery(self):
        c=fixture(False);c['report']['all_local_outcomes_equal']=True;c['sha256']=digest(c['report'])
        with self.assertRaisesRegex(AuditError,'INCONSISTENT'):reconcile_campaign(c)
    def test_audit_append(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'audit.db';b=Path(d)/'anchor.db'
            result=reconcile_and_audit(fixture(),a,b)
            self.assertEqual(result['audit']['seq'],1);self.assertEqual(verify_anchored(a,b)['entries'],1)
    def test_stale_head(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'audit.db';b=Path(d)/'anchor.db';reconcile_and_audit(fixture(),a,b)
            with self.assertRaisesRegex(AuditError,'STALE_HEAD'):reconcile_and_audit(fixture(),a,b,expected_head='0'*64)
if __name__=='__main__':unittest.main()
