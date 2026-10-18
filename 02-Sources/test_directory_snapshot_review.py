import copy
import unittest
from directory_snapshot_review import review_directory_snapshots,verify_directory_snapshot_review,DirectorySnapshotError
from identity_mapping_matrix import build_mapping_matrix

def ident(system,realm,kind,id_type,identifier):
    return dict(system=system,realm=realm,kind=kind,id_type=id_type,identifier=identifier)
S=ident('AD','example','user','SID','S-1-5-21-100')
T=ident('POSIX','local','user','UID','1000')
G=ident('AD','example','group','SID','S-1-5-21-200')
def matrix(): return build_mapping_matrix([dict(source=S,target=T,evidence_ref='ticket-1')])
def snaps(groups=None): return [dict(identity=S,snapshot_ref='ad-1',groups=groups or []),dict(identity=T,snapshot_ref='posix-1',groups=[])]
class Tests(unittest.TestCase):
    def test_present(self):
        b=review_directory_snapshots(matrix(),snaps());self.assertEqual(b['report']['findings'][0]['status'],'SNAPSHOTS_PRESENT_UNAUTHENTICATED');self.assertTrue(verify_directory_snapshot_review(b,matrix(),snaps()))
    def test_missing(self):self.assertEqual(review_directory_snapshots(matrix(),snaps()[:1])['report']['findings'][0]['status'],'MISSING_SNAPSHOT')
    def test_groups(self):self.assertEqual(review_directory_snapshots(matrix(),snaps([G]))['report']['findings'][0]['status'],'GROUP_MEMBERSHIP_UNVERIFIED')
    def test_duplicate_snapshot(self):
        with self.assertRaises(DirectorySnapshotError):review_directory_snapshots(matrix(),snaps()+snaps()[:1])
    def test_duplicate_group(self):
        with self.assertRaises(DirectorySnapshotError):review_directory_snapshots(matrix(),snaps([G,G]))
    def test_invalid_group_kind(self):
        with self.assertRaises(DirectorySnapshotError):review_directory_snapshots(matrix(),snaps([S]))
    def test_invalid_ref(self):
        a=snaps();a[0]['snapshot_ref']='bad\nref'
        with self.assertRaises(DirectorySnapshotError):review_directory_snapshots(matrix(),a)
    def test_invalid_snapshot(self):
        with self.assertRaises(DirectorySnapshotError):review_directory_snapshots(matrix(),[{}])
    def test_tamper(self):
        a=snaps();b=review_directory_snapshots(matrix(),a);b['report']['directory_verified']=True
        with self.assertRaises(DirectorySnapshotError):verify_directory_snapshot_review(b,matrix(),a)
    def test_deterministic(self):self.assertEqual(review_directory_snapshots(matrix(),snaps())['sha256'],review_directory_snapshots(matrix(),list(reversed(snaps())))['sha256'])
    def test_no_qualification(self):self.assertFalse(review_directory_snapshots(matrix(),snaps())['report']['production_qualified'])
if __name__=='__main__':unittest.main()
