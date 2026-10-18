import copy
import tempfile
import unittest
from pathlib import Path
from human_approval_registry import ApprovalRegistry, ApprovalError, digest

class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'reviews.sqlite'
        self.bundle={'report':{'migration_id':'m1','status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}}
        self.bundle['sha256']=digest(self.bundle['report'])
        self.reg=ApprovalRegistry(self.path)
    def tearDown(self): self.reg.close(); self.temp.cleanup()
    def submit(self, **kwargs): return self.reg.submit('r1','m1',self.bundle,'operator',100,now=1000,**kwargs)
    def test_submit_check(self):
        self.assertFalse(self.submit()['cutover_authorized'])
        self.assertEqual(self.reg.check('r1','m1',self.bundle,now=1001)['status'],'REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED')
    def test_expiration(self):
        self.submit(); self.assertEqual(self.reg.check('r1','m1',self.bundle,now=1100)['status'],'EXPIRED')
    def test_revoke(self):
        self.submit(); self.reg.revoke('r1','withdrawn',now=1002)
        self.assertEqual(self.reg.check('r1','m1',self.bundle,now=1003)['status'],'REVOKED')
    def test_duplicate_rejected(self):
        self.submit()
        with self.assertRaises(Exception): self.submit()
    def test_revoke_twice(self):
        self.submit(); self.reg.revoke('r1','withdrawn',now=1002)
        with self.assertRaises(ApprovalError): self.reg.revoke('r1','again',now=1003)
    def test_changed_evidence(self):
        self.submit(); other=copy.deepcopy(self.bundle); other['report']['new']='change'; other['sha256']=digest(other['report'])
        self.assertEqual(self.reg.check('r1','m1',other,now=1001)['status'],'EVIDENCE_CHANGED')
    def test_tampered_bundle(self):
        other=copy.deepcopy(self.bundle); other['report']['status']='BLOCKED'
        with self.assertRaises(ApprovalError): self.reg.submit('r1','m1',other,'operator',100,now=1000)
    def test_blocked_status(self):
        self.bundle['report']['status']='BLOCKED'; self.bundle['sha256']=digest(self.bundle['report'])
        with self.assertRaises(ApprovalError): self.submit()
    def test_invalid_ttl(self):
        with self.assertRaises(ApprovalError): self.reg.submit('r1','m1',self.bundle,'operator',0,now=1000)
    def test_missing(self): self.assertEqual(self.reg.check('absent','m1',self.bundle,now=1001)['status'],'MISSING')
    def test_persistence(self):
        self.submit(); self.reg.close(); self.reg=ApprovalRegistry(self.path)
        self.assertEqual(self.reg.check('r1','m1',self.bundle,now=1001)['status'],'REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED')
    def test_wrong_migration(self):
        self.submit(); self.assertEqual(self.reg.check('r1','m2',self.bundle,now=1001)['status'],'EVIDENCE_CHANGED')

if __name__=='__main__': unittest.main()
