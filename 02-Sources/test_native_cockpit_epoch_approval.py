import copy
import tempfile
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch,verify_epochs
from native_cockpit_epoch_approval import sign_approval,apply_approved_rotation

class EpochApprovalTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.db=Path(self.tmp.name)/'audit.db';self.keys={'old':b'A'*32,'new':b'B'*32};self.gw=b'G'*32
  self.state=transact_epoch(self.db,keys=self.keys,operation='START',key_id='old')
  self.a=sign_approval(gateway_key=self.gw,request_id='request-123',requester='alice',reviewer='bob',old_key_id='old',new_key_id='new',expected_head=self.state['head'])
 def apply(self,a=None,**kw):return apply_approved_rotation(self.db,keys=self.keys,approval=a or self.a,gateway_key=kw.get('gateway_key',self.gw))
 def test_rotation_and_verification(self):
  r=self.apply();self.assertTrue(r['approval_recorded']);self.assertEqual(verify_epochs(self.db,keys=self.keys)['active_key_id'],'new')
 def test_replay_denied(self):
  self.apply()
  with self.assertRaises(ValueError):self.apply()
 def test_wrong_gateway_key(self):
  with self.assertRaises(ValueError):self.apply(gateway_key=b'X'*32)
 def test_tampered_reviewer(self):
  a=copy.deepcopy(self.a);a['payload']['reviewer']='eve'
  with self.assertRaises(ValueError):self.apply(a)
 def test_stale_head(self):
  transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='f'*64)
  with self.assertRaises(ValueError):self.apply()
 def test_self_approval_denied(self):
  with self.assertRaises(ValueError):sign_approval(gateway_key=self.gw,request_id='request-123',requester='alice',reviewer='alice',old_key_id='old',new_key_id='new',expected_head=self.state['head'])
 def test_missing_new_key(self):
  del self.keys['new']
  with self.assertRaises(ValueError):self.apply()
 def test_no_partial_write_on_rejection(self):
  a=copy.deepcopy(self.a);a['gateway_mac']='0'*64
  with self.assertRaises(ValueError):self.apply(a)
  self.assertEqual(verify_epochs(self.db,keys=self.keys)['count'],1)
