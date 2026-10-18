import unittest
from acl_ace_compare import compare_ace_snapshots, verify_ace_comparison, ACEComparisonError

A={'principal':'user:1000','type':'ALLOW','rights':['READ','WRITE'],'flags':['FILE_INHERIT'],'inherited':False}
B={'principal':'group:2000','type':'DENY','rights':['WRITE'],'flags':[],'inherited':True}

class ACECompareTests(unittest.TestCase):
    def test_equal(self):
        r=compare_ace_snapshots([A,B],[A,B],protocol='NFSv4')
        self.assertEqual(r['report']['status'],'STRUCTURAL_MATCH_ONLY')
        self.assertFalse(r['report']['cutover_authorized'])
        self.assertTrue(verify_ace_comparison(r,[A,B],[A,B],protocol='NFSv4'))
    def test_order_matters(self):
        self.assertEqual(compare_ace_snapshots([A,B],[B,A],protocol='SMB')['report']['status'],'BLOCKED_ACE_DRIFT')
    def test_missing_ace(self):
        self.assertEqual(compare_ace_snapshots([A,B],[A],protocol='SMB')['report']['changed_positions'],[1])
    def test_changed_rights(self):
        b={**A,'rights':['READ']}
        self.assertEqual(compare_ace_snapshots([A],[b],protocol='NFSv4')['report']['status'],'BLOCKED_ACE_DRIFT')
    def test_changed_inheritance(self):
        b={**A,'inherited':True}
        self.assertEqual(compare_ace_snapshots([A],[b],protocol='SMB')['report']['status'],'BLOCKED_ACE_DRIFT')
    def test_reordered_rights_equivalent_structure(self):
        b={**A,'rights':['WRITE','READ']}
        self.assertEqual(compare_ace_snapshots([A],[b],protocol='SMB')['report']['status'],'STRUCTURAL_MATCH_ONLY')
    def test_invalid_protocol(self):
        with self.assertRaises(ACEComparisonError): compare_ace_snapshots([],[],protocol='NFSv3')
    def test_unknown_fields(self):
        with self.assertRaises(ACEComparisonError): compare_ace_snapshots([{**A,'unexpected':1}],[],protocol='SMB')
    def test_duplicate_rights(self):
        with self.assertRaises(ACEComparisonError): compare_ace_snapshots([{**A,'rights':['READ','READ']}],[],protocol='SMB')
    def test_tamper(self):
        r=compare_ace_snapshots([A],[A],protocol='SMB');r['report']['status']='CERTIFIED'
        with self.assertRaises(ACEComparisonError): verify_ace_comparison(r,[A],[A],protocol='SMB')
    def test_deterministic(self):
        self.assertEqual(compare_ace_snapshots([A],[B],protocol='SMB'),compare_ace_snapshots([A],[B],protocol='SMB'))

if __name__=='__main__': unittest.main()
