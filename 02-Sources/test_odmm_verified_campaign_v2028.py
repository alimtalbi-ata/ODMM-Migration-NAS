import copy
import os
import tempfile
import unittest
from pathlib import Path
from odmm_access_attestation_v2027 import collect
from odmm_verified_campaign_v2028 import qualify,verify_report

class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        a=self.root/'source'; b=self.root/'target'; a.mkdir();b.mkdir()
        (a/'data').write_bytes(b'hello');(b/'data').write_bytes(b'hello')
        self.skey=b's'*32; self.tkey=b't'*32
        self.s=collect(str(a),'data',expected_euid=os.geteuid(),key=self.skey,key_id='source-key',campaign_id='c1')
        self.t=collect(str(b),'data',expected_euid=os.geteuid(),key=self.tkey,key_id='target-key',campaign_id='c1')
        self.kw=dict(source_key=self.skey,target_key=self.tkey,source_key_id='source-key',target_key_id='target-key',campaign_id='c1',principal_mapping={'UID:'+str(os.geteuid()):'UID:'+str(os.geteuid())},ledger_path=str(self.root/'ledger.sqlite'))
    def tearDown(self): self.temp.cleanup()
    def run_campaign(self,s=None,t=None,**kw):
        options={**self.kw,**kw}
        return qualify([self.s] if s is None else s,[self.t] if t is None else t,**options)
    def test_match(self):
        r=self.run_campaign();self.assertEqual(r['status'],'MATCH');self.assertTrue(verify_report(r));self.assertTrue(r['attestation_cryptographically_verified'])
    def test_replay(self):
        self.run_campaign()
        with self.assertRaisesRegex(ValueError,'REPLAY'):self.run_campaign()
    def test_tamper(self):
        e=copy.deepcopy(self.s);e['payload']['decision']='DENY'
        with self.assertRaisesRegex(ValueError,'INVALID_ATTESTATION'):self.run_campaign(s=[e])
    def test_atomic_invalid_batch(self):
        e=copy.deepcopy(self.s);e['signature']='0'*64
        with self.assertRaises(ValueError):self.run_campaign(s=[self.s,e])
        self.assertEqual(self.run_campaign()['status'],'MATCH')
    def test_duplicate(self):
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):self.run_campaign(s=[self.s,self.s])
    def test_wrong_key(self):
        with self.assertRaisesRegex(ValueError,'INVALID_ATTESTATION'):self.run_campaign(source_key=b'x'*32)
    def test_wrong_campaign(self):
        with self.assertRaisesRegex(ValueError,'INVALID_ATTESTATION'):self.run_campaign(campaign_id='other')
    def test_same_key(self):
        with self.assertRaisesRegex(ValueError,'KEYS_MUST_DIFFER'):self.run_campaign(target_key=self.skey)
    def test_missing_target(self):self.assertEqual(self.run_campaign(t=[])['status'],'UNVERIFIED')
    def test_mapping_missing(self):self.assertEqual(self.run_campaign(principal_mapping={})['status'],'UNVERIFIED')
    def test_report_tamper(self):
        r=self.run_campaign();r['status']='MISMATCH';self.assertFalse(verify_report(r))
    def test_invalid_ledger(self):
        with self.assertRaisesRegex(ValueError,'INVALID_CAMPAIGN_OR_LEDGER'):self.run_campaign(ledger_path=':memory:')
    def test_no_nas_writes(self):
        self.run_campaign();self.assertEqual((self.root/'source'/'data').read_bytes(),b'hello');self.assertEqual((self.root/'target'/'data').read_bytes(),b'hello')
if __name__=='__main__':unittest.main()
