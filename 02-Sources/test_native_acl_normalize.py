import unittest
from native_acl_normalize import *

class NativeACLTests(unittest.TestCase):
    def test_nfs(self):
        self.assertEqual(parse_nfs4('A::OWNER@:rwa')[0]['principal'],'OWNER@')
    def test_nfs_order(self):
        self.assertEqual(compare_native_acl('A::OWNER@:rwa\nD::EVERYONE@:w','D::EVERYONE@:w\nA::OWNER@:rwa',protocol='NFSv4')['report']['status'],'BLOCKED_ACE_DRIFT')
    def test_nfs_same(self):
        self.assertEqual(compare_native_acl('A::OWNER@:rwa','A::OWNER@:awr',protocol='NFSv4')['report']['status'],'STRUCTURAL_MATCH_ONLY')
    def test_nfs_unknown(self):
        with self.assertRaises(NativeACLParseError): parse_nfs4('something unexpected')
    def test_nfs_duplicate(self):
        with self.assertRaises(NativeACLParseError): parse_nfs4('A::OWNER@:rr')
    def test_smb(self):
        self.assertEqual(parse_smb('ACL:S-1-5-21-123:ALLOWED/0x10/0x00120089')[0]['inherited'],True)
    def test_smb_drift(self):
        a='ACL:S-1-5-21-123:ALLOWED/0x0/0x00120089'
        b='ACL:S-1-5-21-123:ALLOWED/0x0/0x001f01ff'
        self.assertEqual(compare_native_acl(a,b,protocol='SMB')['report']['status'],'BLOCKED_ACE_DRIFT')
    def test_smb_unknown(self):
        with self.assertRaises(NativeACLParseError): parse_smb('ACL:EVERYONE:ALLOWED/0x0/0x1')
    def test_empty(self):
        with self.assertRaises(NativeACLParseError): parse_nfs4('')
    def test_protocol(self):
        with self.assertRaises(NativeACLParseError): compare_native_acl('a','b',protocol='NFSv3')
    def test_hash_stable(self):
        a='A::OWNER@:rwa'
        self.assertEqual(compare_native_acl(a,a,protocol='NFSv4'),compare_native_acl(a,a,protocol='NFSv4'))

if __name__=='__main__': unittest.main()
