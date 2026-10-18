import tempfile
import unittest
from pathlib import Path
from native_rotation_access_audit import AccessAudit
from native_rotation_external_verifier import verify_external_state

class ExternalVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.audit=AccessAudit(Path(self.tmp.name)/'audit.db',key=b'k'*32)
        self.audit.append({'event_id':'admit:r1','event':'rotation_access_allowed','request_id':'r1'})
        self.calls=[]
    def tearDown(self): self.tmp.cleanup()
    def observe(self,asset):
        self.calls.append(asset)
        return {'asset_id':asset,'state':'READY','source':'read-only-agent','observed_at':'2026-10-14T00:00:00Z','evidence':{'serial':'123'}}
    def run_check(self,**kw):
        args=dict(audit=self.audit,request_id='r1',verifier='operator2',asset_id='array1',expected_state='READY',observer=self.observe,verify_identity=lambda v,r:True)
        args.update(kw)
        return verify_external_state(**args)
    def test_matches(self):
        x=self.run_check(); self.assertEqual(x['observation'],'MATCHES_EXPECTED'); self.assertFalse(x['retry_allowed'])
    def test_mismatch(self): self.assertEqual(self.run_check(expected_state='OTHER')['observation'],'DIFFERS_FROM_EXPECTED')
    def test_unauthorized_no_observe(self):
        with self.assertRaises(ValueError): self.run_check(verify_identity=lambda v,r:False)
        self.assertEqual(self.calls,[])
    def test_unknown_request_no_observe(self):
        with self.assertRaises(ValueError): self.run_check(request_id='unknown')
        self.assertEqual(self.calls,[])
    def test_invalid_asset_no_observe(self):
        with self.assertRaises(ValueError): self.run_check(asset_id='../bad')
        self.assertEqual(self.calls,[])
    def test_wrong_asset(self):
        with self.assertRaises(ValueError): self.run_check(observer=lambda a:{**self.observe(a),'asset_id':'other'})
    def test_missing_provenance(self):
        with self.assertRaises(ValueError): self.run_check(observer=lambda a:{**self.observe(a),'source':''})
    def test_large_evidence(self):
        with self.assertRaises(ValueError): self.run_check(observer=lambda a:{**self.observe(a),'evidence':{'blob':'x'*70000}})
    def test_duplicate_no_reobservation_retry(self):
        self.run_check()
        with self.assertRaises(ValueError): self.run_check()
        self.assertEqual(len(self.calls),2) # read-only repeat, never effect retry
    def test_audit_corruption_blocks_observation(self):
        import sqlite3
        with sqlite3.connect(self.audit.path) as db: db.execute("UPDATE access_audit SET payload='bad' WHERE seq=1")
        with self.assertRaises(ValueError): self.run_check()
        self.assertEqual(self.calls,[])

if __name__=='__main__': unittest.main()
