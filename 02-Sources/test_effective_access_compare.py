import copy
import unittest
from effective_access_compare import compare_effective_access, verify_comparison, AccessComparisonError

def obs(decision='ALLOW', action='read'):
    return {'principal_alias':'userA','object_alias':'fileA','action':action,'decision':decision}
class EffectiveAccessTests(unittest.TestCase):
    def test_match(self):
        b=compare_effective_access('SMB',[obs()],[obs()]); self.assertTrue(b['report']['equivalent_observations']); self.assertTrue(verify_comparison(b))
    def test_mismatch(self):
        b=compare_effective_access('NFSv4',[obs('ALLOW')],[obs('DENY')]); self.assertEqual(b['report']['summary']['MISMATCH'],1)
    def test_unknown(self):
        b=compare_effective_access('SMB',[obs('UNKNOWN')],[obs()]); self.assertEqual(b['report']['summary']['INDETERMINATE'],1)
    def test_missing(self):
        b=compare_effective_access('SMB',[obs()],[obs(action='delete')]); self.assertEqual(b['report']['summary']['INDETERMINATE'],2)
    def test_duplicate(self): self.assertRaises(AccessComparisonError,compare_effective_access,'SMB',[obs(),obs()],[obs()])
    def test_invalid_action(self): self.assertRaises(AccessComparisonError,compare_effective_access,'SMB',[obs(action='execute')],[obs()])
    def test_invalid_protocol(self): self.assertRaises(AccessComparisonError,compare_effective_access,'NFSv3',[obs()],[obs()])
    def test_empty(self): self.assertRaises(AccessComparisonError,compare_effective_access,'SMB',[],[obs()])
    def test_tamper(self):
        b=compare_effective_access('SMB',[obs()],[obs()]); b['report']['production_qualified']=True; self.assertRaises(AccessComparisonError,verify_comparison,b)
    def test_stable_order(self):
        a=[obs(action='read'),obs(action='write')]; self.assertEqual(compare_effective_access('SMB',a,a),compare_effective_access('SMB',list(reversed(a)),list(reversed(a))))
    def test_no_qualification(self):
        b=compare_effective_access('SMB',[obs()],[obs()]); self.assertFalse(b['report']['production_qualified']); self.assertFalse(b['report']['live_access_test_performed'])
if __name__=='__main__': unittest.main()
