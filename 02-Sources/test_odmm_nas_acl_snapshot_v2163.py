import hashlib,hmac,json,sqlite3,tempfile,unittest
from pathlib import Path
from odmm_nas_acl_export_v2148 import canonical
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_snapshot_v2163 import verified_snapshot_page

KEY=b'test-only-key-32-bytes-xxxxxxxxxxxxxxxx'

def document():
    body={'schema':'odmm.nas.acl.audit.export.v2148','protocol':'NFS4','reports':[],'cutover_authorized':False}
    body['payload_sha256']=hashlib.sha256(canonical(body)).hexdigest()
    return {**body,'signature':hmac.new(KEY,canonical(body),hashlib.sha256).hexdigest()}

class TestSnapshot(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.history=AuditHistory(Path(self.temp.name)/'db.sqlite',KEY)
        for _ in range(4):self.history.record(document())
    def test_page_and_head(self):
        page=verified_snapshot_page(self.history,limit=2)
        self.assertEqual([x['seq'] for x in page['items']],[1,2])
        self.assertEqual(page['next_cursor'],2)
        self.assertEqual(page['verified_head_seq'],4)
        self.assertFalse(page['external_anchor_verified'])
    def test_next_page(self):
        self.assertEqual([x['seq'] for x in verified_snapshot_page(self.history,cursor=2)['items']],[3,4])
    def test_corruption_beyond_first_batch(self):
        for _ in range(260):self.history.record(document())
        with sqlite3.connect(self.history.path) as db:
            db.execute("UPDATE acl_audit_history SET report='{}' WHERE seq=260")
        with self.assertRaises(ValueError):verified_snapshot_page(self.history,batch_size=64)
    def test_sequence_gap(self):
        with sqlite3.connect(self.history.path) as db:db.execute('DELETE FROM acl_audit_history WHERE seq=2')
        with self.assertRaises(ValueError):verified_snapshot_page(self.history)
    def test_invalid_bounds(self):
        for opts in ({'limit':101},{'cursor':-1},{'batch_size':0}):
            with self.assertRaises(ValueError):verified_snapshot_page(self.history,**opts)

if __name__=='__main__':unittest.main()
