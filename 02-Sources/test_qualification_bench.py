import unittest
from qualification_bench import run_fixture,matrix_report,BenchError
from vendor_qualification import CHECKS

def fixture(vendor='NetApp', protocol='NFSv4'):
    return {'vendor':vendor,'protocol':protocol,'endpoint_alias':'lab-a',
            'observations':{c:{'expected':'value','actual':'value'} for c in CHECKS}}

class BenchTests(unittest.TestCase):
    def test_pass_is_simulated_only(self):
        result=run_fixture(fixture()); self.assertTrue(result['report']['simulated_pass']); self.assertFalse(result['report']['production_qualified'])
    def test_failure(self):
        f=fixture(); f['observations']['effective_access']['actual']='denied'; self.assertFalse(run_fixture(f)['report']['simulated_pass'])
    def test_missing_check(self):
        f=fixture(); del f['observations']['audit_integrity']; self.assertRaises(BenchError,run_fixture,f)
    def test_invalid_vendor(self): self.assertRaises(BenchError,run_fixture,fixture('Unknown'))
    def test_invalid_protocol(self): self.assertRaises(BenchError,run_fixture,fixture(protocol='NFSv3'))
    def test_invalid_alias(self):
        f=fixture(); f['endpoint_alias']='../escape'; self.assertRaises(BenchError,run_fixture,f)
    def test_duplicate(self): self.assertRaises(BenchError,matrix_report,[fixture(),fixture()])
    def test_order_independent(self):
        a=fixture(); b=fixture('Dell','SMB'); self.assertEqual(matrix_report([a,b]),matrix_report([b,a]))
    def test_digest_stable(self): self.assertEqual(run_fixture(fixture()),run_fixture(fixture()))
    def test_wrong_observation_shape(self):
        f=fixture(); f['observations']['mount_identity']={'status':'PASS'}; self.assertRaises(BenchError,run_fixture,f)

if __name__=='__main__': unittest.main()
