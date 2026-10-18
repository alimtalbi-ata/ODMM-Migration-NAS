import unittest
from odmm_market_readiness_v22812 import REQUIRED, evaluate
class Tests(unittest.TestCase):
 def test_empty(self):
  r=evaluate({}); self.assertEqual(len(r["blocked_checks"]),len(REQUIRED)); self.assertFalse(r["cutover_authorized"])
 def test_complete_is_not_authorized(self):
  r=evaluate({k:{"status":"PASS","evidence_id":"EV-"+k} for k in REQUIRED}); self.assertEqual(r["blocked_checks"],[]); self.assertFalse(r["cutover_authorized"])
 def test_pass_without_evidence_is_unverified(self):
  self.assertEqual(evaluate({"acl_fidelity":{"status":"PASS"}})["checks"]["acl_fidelity"],"UNVERIFIED")
 def test_fail(self):
  self.assertEqual(evaluate({"content_integrity":{"status":"FAIL"}})["checks"]["content_integrity"],"FAIL")
 def test_bad_type(self):
  with self.assertRaises(ValueError): evaluate([])
 def test_unknown_status(self):
  self.assertEqual(evaluate({"approval":{"status":"DONE","evidence_id":"x"}})["checks"]["approval"],"UNVERIFIED")
if __name__=="__main__": unittest.main()
