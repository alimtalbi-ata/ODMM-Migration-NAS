import os, sys, tempfile, unittest
from collector_policy import bounded_run, PolicyError

@unittest.skipUnless(sys.platform.startswith("linux"), "Linux resource limits")
class CollectorLimitsTests(unittest.TestCase):
    def test_normal_output(self):
        r=bounded_run(["/bin/echo","ok"],timeout=3)
        self.assertEqual(r.returncode,0)
    def test_kernel_output_limit(self):
        with tempfile.TemporaryDirectory() as d:
            p=os.path.join(d,"flood")
            with open(p,"w") as f: f.write("#!/usr/bin/env python3\nimport os\nos.write(1,b'x'*100000)\n")
            os.chmod(p,0o700)
            with self.assertRaises(PolicyError): bounded_run([p,"unused"],timeout=3,max_output=4096)
    def test_invalid_limits(self):
        with self.assertRaises(PolicyError): bounded_run([sys.executable,"-c"],timeout=61)
    def test_invalid_argv(self):
        with self.assertRaises(PolicyError): bounded_run([sys.executable])
