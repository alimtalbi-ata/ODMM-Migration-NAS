import tempfile
import unittest
from pathlib import Path
from native_benchmark_authenticated import append_authenticated
from native_benchmark_recovery_plan import prepare_recovery, validate_manual_approval

class RecoveryPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'audit.jsonl'
        self.keys={'one':b'1'*32}
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','error_count':0,'cutover_authorized':False,'source_read_only':True,'isolated_copy':True}
    def damaged(self):
        append_authenticated(self.path,self.report,keys=self.keys,key_id='one')
        with self.path.open('ab') as f:f.write(b'{broken')
    def test_missing_non_mutating(self):
        p=prepare_recovery(self.path,keys=self.keys)
        self.assertEqual(p['status'],'NO_REPAIR_REQUIRED');self.assertFalse(self.path.exists())
    def test_valid_no_repair(self):
        append_authenticated(self.path,self.report,keys=self.keys,key_id='one')
        self.assertEqual(prepare_recovery(self.path,keys=self.keys)['status'],'NO_REPAIR_REQUIRED')
    def test_damaged_evidence_preserved(self):
        self.damaged();before=self.path.read_bytes();p=prepare_recovery(self.path,keys=self.keys)
        self.assertEqual(p['status'],'REVIEW_REQUIRED');self.assertEqual(before,self.path.read_bytes());self.assertEqual(p['evidence_bytes'],len(before))
    def test_no_approval_without_reason(self):
        self.damaged();p=prepare_recovery(self.path,keys=self.keys)
        with self.assertRaises(ValueError):validate_manual_approval(p,evidence_sha256=p['evidence_sha256'],operator='reviewer1',rationale='',approval_token='token1234')
    def test_approval_no_mutation(self):
        self.damaged();before=self.path.read_bytes();p=prepare_recovery(self.path,keys=self.keys)
        r=validate_manual_approval(p,evidence_sha256=p['evidence_sha256'],operator='reviewer1',rationale='Investigate broken tail',approval_token='token1234')
        self.assertFalse(r['repair_authorized']);self.assertFalse(r['mutations_performed']);self.assertEqual(before,self.path.read_bytes())
    def test_evidence_mismatch(self):
        self.damaged();p=prepare_recovery(self.path,keys=self.keys)
        with self.assertRaises(ValueError):validate_manual_approval(p,evidence_sha256='0'*64,operator='reviewer1',rationale='Investigate broken tail',approval_token='token1234')
    def test_healthy_cannot_approve(self):
        p=prepare_recovery(self.path,keys=self.keys)
        with self.assertRaises(ValueError):validate_manual_approval(p,evidence_sha256='0'*64,operator='reviewer1',rationale='Investigate broken tail',approval_token='token1234')
