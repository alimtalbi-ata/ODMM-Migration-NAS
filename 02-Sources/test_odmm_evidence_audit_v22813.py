import unittest
from odmm_evidence_audit_v22813 import audit
from odmm_market_readiness_v22812 import REQUIRED

def fixture():
    return {k:{"status":"PASS","evidence_id":"EV-"+k,"job_id":"J-1"} for k in REQUIRED}
class EvidenceAuditTests(unittest.TestCase):
    def test_complete_still_not_authorized(self):
        r=audit(fixture(),"J-1"); self.assertFalse(r["cutover_authorized"]); self.assertFalse(r["anomalies"])
    def test_duplicate_evidence_blocked(self):
        e=fixture(); e["approval"]["evidence_id"]=e["inventory"]["evidence_id"]
        self.assertEqual(audit(e,"J-1")["anomalies"][0]["reason"],"DUPLICATE_EVIDENCE_ID")
    def test_wrong_job_blocked(self):
        e=fixture(); e["acl_fidelity"]["job_id"]="J-2"
        self.assertEqual(audit(e,"J-1")["anomalies"][0]["reason"],"JOB_BINDING_MISMATCH")
    def test_missing_check_blocked(self):
        e=fixture(); del e["effective_access"]
        self.assertIn("effective_access",audit(e,"J-1")["blocked_checks"])
    def test_invalid_document(self):
        with self.assertRaises(ValueError): audit([],"J-1")
if __name__=="__main__": unittest.main()
