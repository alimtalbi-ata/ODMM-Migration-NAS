import os, sys, unittest
from collector_policy import precheck, bounded_run, PolicyError

class PolicyTests(unittest.TestCase):
    def test_missing_tool_fails_closed(self):
        with self.assertRaises(PolicyError): precheck('SMB',executable_lookup=lambda _:None)
    def test_unknown_protocol(self):
        with self.assertRaises(PolicyError): precheck('NFSv3')
    def test_capability_unqualified(self):
        v=precheck('NFSv4',executable_lookup=lambda _: '/usr/bin/nfs4_getfacl')
        self.assertFalse(v['production_qualified'])
        self.assertFalse(v['effective_access'])
    def test_bounded_success(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path=os.path.join(d,'hello.sh')
            with open(path,'w') as handle:
                handle.write('#!/bin/sh\nprintf hello\n')
            os.chmod(path,0o700)
            r=bounded_run([path,'ignored'],timeout=3)
            self.assertEqual(r.stdout,b'hello')
    def test_nonabsolute_executable(self):
        with self.assertRaises(PolicyError): bounded_run(['python','x'])
    def test_output_limit(self):
        with self.assertRaises(PolicyError): bounded_run(['/bin/echo','x'*100],max_output=5)
    def test_timeout(self):
        with self.assertRaises(PolicyError): bounded_run([sys.executable,'-c'],timeout=0)
