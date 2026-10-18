import copy
import unittest
from identity_acl import Principal, IdentityMap
from odmm_acl_file_qualification_v2025 import qualify, verify

class TestACLFileQualification(unittest.TestCase):
    def setUp(self):
        self.src = Principal('ad', 'user', '100', 'u')
        self.dst = Principal('ad2', 'user', 'S-1', 'u')
        self.mapping = IdentityMap([(self.src, self.dst)])
        self.a = {'a.txt': {'status': 'COLLECTED_UNVERIFIED', 'protocol': 'NFSV4', 'entries': ['A::100:r']}}
        self.b = {'a.txt': {'status': 'COLLECTED_UNVERIFIED', 'protocol': 'SMB', 'entries': ['ACL:S-1:ALLOWED/0x0/READ']}}
    def run_pair(self, **kw):
        return qualify(self.a, self.b, {'100': self.src}, {'S-1': self.dst}, self.mapping, **kw)
    def test_canonical_match_not_effective(self):
        r = self.run_pair(identity_verified=True)
        self.assertEqual(r['status'], 'MATCH')
        self.assertFalse(r['effective_access_verified'])
        self.assertFalse(r['cutover_authorized'])
        self.assertTrue(verify(r))
    def test_unverified_identity(self):
        self.assertEqual(self.run_pair()['status'], 'UNVERIFIED')
    def test_deny_mismatch(self):
        self.b['a.txt']['entries'] = ['ACL:S-1:DENIED/0x0/READ']
        self.assertEqual(self.run_pair(identity_verified=True)['status'], 'MISMATCH')
    def test_missing_target(self):
        self.assertEqual(qualify(self.a, {}, {'100': self.src}, {}, self.mapping)['status'], 'UNVERIFIED')
    def test_unknown_right(self):
        self.a['a.txt']['entries'] = ['A::100:z']
        self.assertEqual(self.run_pair(identity_verified=True)['status'], 'UNVERIFIED')
    def test_unmapped_identity(self):
        self.assertEqual(qualify(self.a, self.b, {'100': self.src}, {'S-1': self.dst}, IdentityMap([]), identity_verified=True)['status'], 'UNVERIFIED')
    def test_bad_paths(self):
        for name in ('../secret', '/absolute', 'x//y', 'x\\y', './a'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                qualify({name: self.a['a.txt']}, {}, {}, {}, self.mapping)
    def test_limits(self):
        with self.assertRaises(ValueError): self.run_pair(max_files=0)
        with self.assertRaises(ValueError): self.run_pair(max_files=1, max_aces_per_file=0)
        with self.assertRaises(ValueError): self.run_pair(max_aces_per_file=1 if False else 0)
    def test_tamper(self):
        r = self.run_pair(identity_verified=True)
        r['files'][0]['status'] = 'MISMATCH'
        self.assertFalse(verify(r))
    def test_deterministic(self):
        self.assertEqual(self.run_pair(identity_verified=True)['report_sha256'], self.run_pair(identity_verified=True)['report_sha256'])
    def test_empty(self):
        r = qualify({}, {}, {}, {}, self.mapping)
        self.assertEqual(r['status'], 'UNVERIFIED')
    def test_excessive_aces(self):
        self.a['a.txt']['entries'] = ['A::100:r'] * 3
        self.assertEqual(self.run_pair(max_aces_per_file=2)['status'], 'UNVERIFIED')
    def test_no_writes(self):
        r = self.run_pair(identity_verified=True)
        self.assertFalse(r['writes_to_nas'])
        self.assertTrue(r['native_engine_default'])
        self.assertFalse(r['silent_fallback_allowed'])

if __name__ == '__main__': unittest.main()
