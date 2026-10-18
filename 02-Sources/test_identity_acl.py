import unittest
from identity_acl import Principal, IdentityMap, IdentityConflict, ACE, compare_acl, access_test_matrix

class IdentityAclTests(unittest.TestCase):
    def setUp(self):
        self.src = Principal('AD','user','S-1-5-21-100','person-1')
        self.dst = Principal('LDAP','user','uid=alice','person-1')
        self.map = IdentityMap([(self.src,self.dst)])
    def test_resolve(self):
        self.assertEqual(self.map.resolve(self.src), self.dst)
    def test_missing_mapping_blocks(self):
        result=compare_acl([ACE(Principal('AD','user','unknown','x'),'allow',('read',))],[],self.map)
        self.assertEqual(result['status'],'BLOCKED')
    def test_mismatch_blocks(self):
        result=compare_acl([ACE(self.src,'deny',('write',))],[ACE(self.dst,'allow',('write',))],self.map)
        self.assertEqual(result['status'],'BLOCKED')
    def test_matching_still_indeterminate(self):
        result=compare_acl([ACE(self.src,'allow',('read',))],[ACE(self.dst,'allow',('read',))],self.map,source_complete=True,target_complete=True,identity_verified=True)
        self.assertEqual(result['status'],'INDETERMINATE')
        self.assertFalse(result['effective_access_verified'])
    def test_many_to_one_rejected(self):
        with self.assertRaises(IdentityConflict):
            IdentityMap([(self.src,self.dst),(Principal('AD','user','other','person-2'),self.dst)])
    def test_kind_mismatch_rejected(self):
        with self.assertRaises(IdentityConflict):
            IdentityMap([(self.src,Principal('LDAP','group','g','g'))])
    def test_matrix_not_run(self):
        m=access_test_matrix([self.dst],['/share/a'])
        self.assertEqual(len(m),4)
        self.assertTrue(all(x['result']=='NOT_RUN' for x in m))
if __name__=='__main__': unittest.main()
