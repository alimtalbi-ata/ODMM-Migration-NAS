import tempfile
import unittest
from pathlib import Path
from odmm_campaign_registry_v2029 import Registry, verify_report
H='a'*64
class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'registry.sqlite'; self.r=Registry(self.path)
        self.r.create('campaign',['nas1','nas2'])
    def test_initial(self):
        self.assertEqual(self.r.report('campaign')['counts']['PENDING'],2)
    def test_resume(self):
        self.r.record('campaign','nas1','source','e1','MATCH',H)
        self.assertEqual(Registry(self.path).report('campaign')['counts']['PARTIAL'],1)
    def test_complete(self):
        for side in ('source','target'): self.r.record('campaign','nas1',side,side,'MATCH',H)
        self.assertEqual(self.r.report('campaign')['counts']['COMPLETE'],1)
    def test_mismatch(self):
        self.r.record('campaign','nas1','source','e1','MISMATCH',H)
        self.r.record('campaign','nas1','target','e2','MATCH',H)
        self.assertEqual(self.r.report('campaign')['status'],'MISMATCH')
    def test_unverified(self):
        self.r.record('campaign','nas1','source','e1','UNVERIFIED',H)
        self.r.record('campaign','nas1','target','e2','MATCH',H)
        self.assertEqual(self.r.report('campaign')['counts']['UNVERIFIED'],1)
    def test_replay(self):
        self.r.record('campaign','nas1','source','e1','MATCH',H)
        with self.assertRaisesRegex(ValueError,'REPLAYED'): self.r.record('campaign','nas2','target','e1','MATCH',H)
    def test_idempotent(self):
        self.r.record('campaign','nas1','source','e1','MATCH',H)
        self.assertFalse(self.r.record('campaign','nas1','source','e1','MATCH',H))
    def test_conflict(self):
        self.r.record('campaign','nas1','source','e1','MATCH',H)
        with self.assertRaisesRegex(ValueError,'CONFLICTING'): self.r.record('campaign','nas1','source','e2','MATCH',H)
    def test_manifest_conflict(self):
        with self.assertRaisesRegex(ValueError,'MANIFEST'): self.r.create('campaign',['different'])
    def test_manifest_idempotent(self):
        self.assertEqual(self.r.create('campaign',['nas2','nas1']),self.r.report('campaign')['manifest_sha256'])
    def test_unknown_asset(self):
        with self.assertRaisesRegex(ValueError,'UNKNOWN'): self.r.record('campaign','other','source','e1','MATCH',H)
    def test_invalid_hash(self):
        with self.assertRaisesRegex(ValueError,'HASH'): self.r.record('campaign','nas1','source','e1','MATCH','abc')
    def test_report_tamper(self):
        r=self.r.report('campaign'); self.assertTrue(verify_report(r)); r['cutover_authorized']=True; self.assertFalse(verify_report(r))
    def test_no_memory(self):
        with self.assertRaises(ValueError): Registry(':memory:')
if __name__=='__main__': unittest.main()
