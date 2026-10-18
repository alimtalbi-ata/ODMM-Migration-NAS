import copy
import tempfile
import time
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch,verify_epochs
from native_rotation_target_binding import sign_target_approval,apply_target_bound_rotation

class TargetBoundRotationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.db=Path(self.tmp.name)/'audit.db';self.keys={'old':b'A'*32,'new':b'B'*32,'other':b'C'*32};self.gateway=b'G'*32
  self.now=time.time_ns();self.start=transact_epoch(self.db,keys=self.keys,operation='START',key_id='old')
 def signed(self,**kw):
  p=dict(gateway_key=self.gateway,request_id='req-1941',requester='alice',reviewer='bob',target_key_id='new',expected_head=self.start['head'],issued_ns=self.now-1000,expires_ns=self.now+1000000000)
  p.update(kw);return sign_target_approval(**p)
 def apply(self,signed=None,**kw):return apply_target_bound_rotation(self.db,keys=self.keys,signed=signed or self.signed(),gateway_key=self.gateway,now_ns=self.now,**kw)
 def test_valid(self):self.assertEqual(self.apply()['active_key_id'],'new')
 def test_replay(self):
  s=self.signed();self.apply(s)
  with self.assertRaises(ValueError):self.apply(s)
 def test_target_tamper(self):
  s=self.signed();s['payload']['target_key_id']='other'
  with self.assertRaises(ValueError):self.apply(s)
 def test_wrong_gateway(self):
  with self.assertRaises(ValueError):apply_target_bound_rotation(self.db,keys=self.keys,signed=self.signed(),gateway_key=b'X'*32,now_ns=self.now)
 def test_stale_head(self):
  transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='f'*64)
  with self.assertRaises(ValueError):self.apply()
 def test_expired(self):
  s=self.signed(expires_ns=self.now-1,issued_ns=self.now-1000)
  with self.assertRaises(ValueError):self.apply(s)
 def test_same_identity(self):
  with self.assertRaises(ValueError):self.signed(reviewer='alice')
 def test_same_key(self):
  with self.assertRaises(ValueError):self.apply(self.signed(target_key_id='old'))
 def test_wrong_checkpoint(self):
  with self.assertRaises(ValueError):self.apply(checkpoint={'count':1,'head':'f'*64})
 def test_failed_no_mutation(self):
  with self.assertRaises(ValueError):self.apply(self.signed(target_key_id='other',expected_head='f'*64))
  self.assertEqual(verify_epochs(self.db,keys=self.keys)['head'],self.start['head'])
