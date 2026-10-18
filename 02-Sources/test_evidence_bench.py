import copy
import unittest
from evidence_bench import seal_observation,verify_envelopes,EvidenceError
from vendor_qualification import CHECKS

def envelopes():
    return [seal_observation('NetApp','NFSv4','lab-a',check,'ok','ok') for check in CHECKS]

class EvidenceBenchTests(unittest.TestCase):
    def test_valid_evidence_not_certified(self):
        report=verify_envelopes(envelopes())['report']
        self.assertTrue(report['evidence_integrity_verified'])
        self.assertFalse(report['production_qualified'])
        self.assertFalse(report['effective_access_verified'])
    def test_digest_stable(self): self.assertEqual(verify_envelopes(envelopes()),verify_envelopes(list(reversed(envelopes()))))
    def test_tampering_rejected(self):
        items=envelopes(); items[0]['payload']['actual']='changed'
        self.assertRaises(EvidenceError,verify_envelopes,items)
    def test_duplicate_rejected(self):
        items=envelopes(); items[1]=copy.deepcopy(items[0]); self.assertRaises(EvidenceError,verify_envelopes,items)
    def test_missing_rejected(self): self.assertRaises(EvidenceError,verify_envelopes,envelopes()[:-1])
    def test_mixed_endpoint_rejected(self):
        items=envelopes(); items[0]=seal_observation('Dell','NFSv4','lab-a',CHECKS[0],'ok','ok')
        self.assertRaises(EvidenceError,verify_envelopes,items)
    def test_unknown_source_rejected(self): self.assertRaises(EvidenceError,seal_observation,'NetApp','SMB','lab-a',CHECKS[0],'a','a','network')
    def test_nan_rejected(self): self.assertRaises(EvidenceError,seal_observation,'NetApp','SMB','lab-a',CHECKS[0],float('nan'),'a')
    def test_operator_import_not_verified_provenance(self):
        items=[seal_observation('IBM','SMB','lab-b',c,1,1,'operator-import') for c in CHECKS]
        self.assertFalse(verify_envelopes(items)['report']['evidence_provenance_verified'])
