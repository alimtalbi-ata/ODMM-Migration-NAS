import copy
import unittest
from odmm_effective_access_v2026 import compare, verify

def rec(principal='UID:100', decision='ALLOW', path='dir/a', action='READ_DATA', eid='evidence-001'):
    return dict(path=path, principal=principal, action=action, decision=decision,
                method='INDEPENDENT_READ_ONLY_PROBE', evidence_id=eid)

class Tests(unittest.TestCase):
    def test_match_attested(self):
        r=compare([rec()],[rec('UID:200',eid='evidence-002')],principal_mapping={'UID:100':'UID:200'},source_attested=True,target_attested=True)
        self.assertEqual(r['status'],'MATCH'); self.assertTrue(verify(r)); self.assertFalse(r['cutover_authorized'])
    def test_difference(self):
        r=compare([rec()],[rec('UID:200','DENY')],principal_mapping={'UID:100':'UID:200'},source_attested=True,target_attested=True)
        self.assertEqual(r['status'],'MISMATCH')
    def test_unattested(self):
        self.assertEqual(compare([rec()],[rec('UID:200')],principal_mapping={'UID:100':'UID:200'})['status'],'UNVERIFIED')
    def test_missing(self):
        self.assertEqual(compare([rec()],[],principal_mapping={'UID:100':'UID:200'},source_attested=True,target_attested=True)['status'],'UNVERIFIED')
    def test_unmapped(self):
        self.assertEqual(compare([rec()],[rec('UID:200')],principal_mapping={},source_attested=True,target_attested=True)['status'],'UNVERIFIED')
    def test_duplicate(self):
        self.assertEqual(compare([rec(),rec(eid='evidence-003')],[rec('UID:200')],principal_mapping={'UID:100':'UID:200'},source_attested=True,target_attested=True)['status'],'UNVERIFIED')
    def test_unsafe_action(self):
        x=rec(); x['action']='DELETE'
        with self.assertRaises(ValueError): compare([x],[],principal_mapping={})
    def test_unsafe_method(self):
        x=rec(); x['method']='WRITE_TEST'
        with self.assertRaises(ValueError): compare([x],[],principal_mapping={})
    def test_invalid_path(self):
        with self.assertRaises(ValueError): compare([rec(path='../escape')],[],principal_mapping={})
    def test_limit(self):
        with self.assertRaises(ValueError): compare([rec(),rec()],[],principal_mapping={},max_records=1)
    def test_empty(self):
        self.assertEqual(compare([],[],principal_mapping={})['status'],'UNVERIFIED')
    def test_tamper(self):
        r=compare([],[],principal_mapping={}); r['cutover_authorized']=True
        self.assertFalse(verify(r))
    def test_unmapped_same_identity(self):
        self.assertEqual(compare([rec()],[rec()],principal_mapping={},source_attested=True,target_attested=True)['status'],'UNVERIFIED')

if __name__=='__main__': unittest.main()
