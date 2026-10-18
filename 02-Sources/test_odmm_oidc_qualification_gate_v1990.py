import subprocess
import unittest
from odmm_oidc_qualification_gate_v1990 import run_gate
class GateTests(unittest.TestCase):
    def test_pass(self):
        def runner(cmd,**kw): return subprocess.CompletedProcess(cmd,0,"","Ran 2 tests in 0.01s\\nOK")
        r=run_gate(".",suites=("test_odmm_a",),runner=runner)
        self.assertEqual(r["status"],"PASS_OFFLINE_ONLY")
        self.assertFalse(r["production_qualified"])
    def test_failure(self):
        def runner(cmd,**kw): return subprocess.CompletedProcess(cmd,1,"","FAILED")
        self.assertEqual(run_gate(".",suites=("test_odmm_a",),runner=runner)["status"],"FAIL")
    def test_timeout(self):
        def runner(cmd,**kw): raise subprocess.TimeoutExpired(cmd,1)
        self.assertEqual(run_gate(".",suites=("test_odmm_a",),runner=runner)["results"][0]["status"],"TIMEOUT")
    def test_suite_validation(self):
        with self.assertRaises(ValueError): run_gate(".",suites=("../etc/passwd",))
if __name__=="__main__": unittest.main()
