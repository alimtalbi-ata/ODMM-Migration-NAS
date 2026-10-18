import unittest
from access_evidence import Observation,compare_observations,detect_orphans
from identity_acl import Principal,IdentityMap

def obs(side,outcome='ALLOW',test_id='T1',right='read'):
    return Observation(test_id,side,'canonical:user:1','/test',right,outcome,'evidence-'+side)

class EvidenceTests(unittest.TestCase):
    def test_matching(self):
        r=compare_observations([obs('source'),obs('target')],expected_test_ids=['T1'])
        self.assertEqual(r['status'],'MATCHED_OBSERVATIONS')
        self.assertFalse(r['effective_access_certified'])
    def test_drift(self):
        self.assertEqual(compare_observations([obs('source'),obs('target','DENY')],expected_test_ids=['T1'])['failures'][0]['reason'],'ACCESS_DRIFT')
    def test_missing(self):
        self.assertEqual(compare_observations([obs('source')],expected_test_ids=['T1'])['status'],'BLOCKED')
    def test_unknown(self):
        self.assertEqual(compare_observations([obs('source'),obs('target','UNKNOWN')],expected_test_ids=['T1'])['status'],'BLOCKED')
    def test_duplicate(self):
        with self.assertRaises(ValueError): compare_observations([obs('source'),obs('source')],expected_test_ids=['T1'])
    def test_identity_mismatch(self):
        self.assertEqual(compare_observations([obs('source'),obs('target',right='write')],expected_test_ids=['T1'])['status'],'BLOCKED')
    def test_orphans(self):
        a=Principal('AD','user','S-1','u1'); b=Principal('LDAP','user','uid=1','u1'); c=Principal('AD','user','S-2','u2')
        self.assertEqual(len(detect_orphans([a,c],IdentityMap([(a,b)]))),1)

if __name__=='__main__': unittest.main()
