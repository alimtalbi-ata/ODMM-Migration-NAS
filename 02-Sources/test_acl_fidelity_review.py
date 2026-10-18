import unittest
from acl_fidelity_review import *

BASE='REVISION:1\nOWNER:S-1-5-21-100\nGROUP:S-1-5-21-200\nACL:S-1-5-21-100:ALLOWED/0x0/0x00120089'

class FidelityTests(unittest.TestCase):
    def test_equal_smb(self):
        self.assertEqual(review_acl_fidelity(BASE,BASE,protocol='SMB')['report']['status'],'STRUCTURAL_MATCH_ONLY')
    def test_owner_drift(self):
        other=BASE.replace('OWNER:S-1-5-21-100','OWNER:S-1-5-21-999')
        self.assertEqual(review_acl_fidelity(BASE,other,protocol='SMB')['report']['metadata_drift'],['OWNER'])
    def test_group_drift(self):
        other=BASE.replace('GROUP:S-1-5-21-200','GROUP:S-1-5-21-999')
        self.assertEqual(review_acl_fidelity(BASE,other,protocol='SMB')['report']['status'],'BLOCKED_ACL_FIDELITY_DRIFT')
    def test_revision_drift(self):
        self.assertEqual(review_acl_fidelity(BASE,BASE.replace('REVISION:1','REVISION:2'),protocol='SMB')['report']['metadata_drift'],['REVISION'])
    def test_missing_metadata(self):
        text=BASE.replace('OWNER:S-1-5-21-100\n','')
        self.assertEqual(review_acl_fidelity(text,text,protocol='SMB')['report']['status'],'INDETERMINATE_METADATA')
    def test_duplicate_header(self):
        with self.assertRaises(ACLFidelityError): review_acl_fidelity(BASE+'\nOWNER:S-1-5-21-100',BASE,protocol='SMB')
    def test_bad_sid(self):
        with self.assertRaises(ACLFidelityError): review_acl_fidelity(BASE.replace('OWNER:S-1-5-21-100','OWNER:administrator'),BASE,protocol='SMB')
    def test_ace_drift(self):
        other=BASE.replace('0x00120089','0x001f01ff')
        self.assertEqual(review_acl_fidelity(BASE,other,protocol='SMB')['report']['status'],'BLOCKED_ACL_FIDELITY_DRIFT')
    def test_nfs_indeterminate(self):
        self.assertEqual(review_acl_fidelity('A::OWNER@:rwa','A::OWNER@:rwa',protocol='NFSv4')['report']['status'],'INDETERMINATE_METADATA')
    def test_bad_protocol(self):
        with self.assertRaises(ACLFidelityError): review_acl_fidelity(BASE,BASE,protocol='NFSv3')
    def test_verification(self):
        bundle=review_acl_fidelity(BASE,BASE,protocol='SMB')
        self.assertTrue(verify_acl_fidelity(bundle,BASE,BASE,protocol='SMB'))
        bundle['report']['cutover_authorized']=True
        with self.assertRaises(ACLFidelityError): verify_acl_fidelity(bundle,BASE,BASE,protocol='SMB')
    def test_determinism(self):
        self.assertEqual(review_acl_fidelity(BASE,BASE,protocol='SMB'),review_acl_fidelity(BASE,BASE,protocol='SMB'))

if __name__=='__main__': unittest.main()
