import copy
import unittest
from collector_evidence_bridge import bridge_collection,verify_bridge,missing_checks,BridgeError

COL={'mount_attestation':{'protocol':'NFSv4','mount_id':'42','device':'0:40','source':'server:/private','mountpoint':'/private','fstype':'nfs4'},
     'path_identity':{'device':42,'inode':43,'mode':33188},'limitations':['NO_EFFECTIVE_ACCESS_TEST']}
class BridgeTests(unittest.TestCase):
    def make(self): return bridge_collection('NetApp','NFSv4','lab1',COL)
    def test_valid(self):
        b=self.make(); self.assertTrue(verify_bridge(b)); self.assertFalse(b['report']['production_qualified'])
    def test_stable(self): self.assertEqual(self.make(),self.make())
    def test_redacts_paths_and_source(self):
        b=self.make(); self.assertNotIn('server:/private',str(b)); self.assertNotIn('/private',str(b))
    def test_tamper(self):
        b=self.make(); b['report']['endpoint_alias']='other'; self.assertRaises(BridgeError,verify_bridge,b)
    def test_missing_attestation(self):
        c=copy.deepcopy(COL); c.pop('mount_attestation'); self.assertRaises(BridgeError,bridge_collection,'NetApp','NFSv4','lab1',c)
    def test_protocol_mismatch(self): self.assertRaises(BridgeError,bridge_collection,'NetApp','SMB','lab1',COL)
    def test_unsupported_vendor(self): self.assertRaises(BridgeError,bridge_collection,'Unknown','NFSv4','lab1',COL)
    def test_bad_alias(self): self.assertRaises(BridgeError,bridge_collection,'NetApp','NFSv4','a/b',COL)
    def test_missing_checks(self): self.assertEqual(len(missing_checks()),5)
    def test_unsafe_claim(self):
        b=self.make(); b['report']['production_qualified']=True; self.assertRaises(BridgeError,verify_bridge,b)
if __name__=='__main__': unittest.main()
