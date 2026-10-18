import copy
import unittest
from identity_mapping_matrix import build_mapping_matrix,verify_mapping_matrix,MappingMatrixError

def ident(system='AD',realm='example',kind='user',id_type='SID',identifier='S-1-5-21-100'):
    return dict(system=system,realm=realm,kind=kind,id_type=id_type,identifier=identifier)
def entry(src=None,dst=None,ref='ticket-1'):
    return dict(source=src or ident(),target=dst or ident('POSIX','local','user','UID','1000'),evidence_ref=ref)
class MappingMatrixTests(unittest.TestCase):
    def test_pending(self):
        bundle=build_mapping_matrix([entry()]);self.assertEqual(bundle['report']['status'],'PENDING_DIRECTORY_VERIFICATION');self.assertTrue(verify_mapping_matrix(bundle))
    def test_one_to_many(self):
        a=entry();b=entry(dst=ident('POSIX','local','user','UID','1001'),ref='ticket-2');self.assertEqual(build_mapping_matrix([a,b])['report']['status'],'BLOCKED')
    def test_many_to_one(self):
        a=entry();b=entry(src=ident(identifier='S-1-5-21-101'),ref='ticket-2');self.assertEqual(build_mapping_matrix([a,b])['report']['status'],'BLOCKED')
    def test_duplicate(self):
        with self.assertRaises(MappingMatrixError):build_mapping_matrix([entry(),entry()])
    def test_kind(self):
        with self.assertRaises(MappingMatrixError):build_mapping_matrix([entry(dst=ident('POSIX','local','group','GID','1000'))])
    def test_invalid_sid(self):
        with self.assertRaises(MappingMatrixError):build_mapping_matrix([entry(src=ident(identifier='bad'))])
    def test_invalid_uid(self):
        with self.assertRaises(MappingMatrixError):build_mapping_matrix([entry(dst=ident('POSIX','local','user','UID','-1'))])
    def test_tamper(self):
        b=build_mapping_matrix([entry()]);b['report']['entries'][0]['evidence_ref']='changed'
        with self.assertRaises(MappingMatrixError):verify_mapping_matrix(b)
    def test_forged_verified(self):
        b=build_mapping_matrix([entry()]);b['report']['directory_verified']=True
        with self.assertRaises(MappingMatrixError):verify_mapping_matrix(b)
    def test_deterministic(self):
        a=entry();b=entry(src=ident(identifier='S-1-5-21-101'),dst=ident('POSIX','local','user','UID','1001'),ref='ticket-2')
        self.assertEqual(build_mapping_matrix([a,b])['sha256'],build_mapping_matrix([b,a])['sha256'])
    def test_empty(self):
        with self.assertRaises(MappingMatrixError):build_mapping_matrix([])
if __name__=='__main__':unittest.main()
