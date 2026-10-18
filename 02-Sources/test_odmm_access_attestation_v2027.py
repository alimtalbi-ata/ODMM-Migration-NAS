import copy
import os
import tempfile
import unittest
from pathlib import Path
from odmm_access_attestation_v2027 import collect, verify, as_comparison_record
from odmm_effective_access_v2026 import compare

KEY = b'key-for-test-only-not-for-production!' * 2

class TestAccessAttestation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        Path(self.temp.name, 'data').write_bytes(b'hello')
        self.kw = dict(key=KEY, key_id='qualification-key', campaign_id='campaign-01')
        self.e = collect(self.temp.name, 'data', expected_euid=os.geteuid(), **self.kw)
    def tearDown(self): self.temp.cleanup()
    def test_valid(self): self.assertTrue(verify(self.e, key=KEY, expected_key_id='qualification-key', expected_campaign_id='campaign-01'))
    def test_record(self): self.assertEqual(as_comparison_record(self.e, key=KEY, expected_key_id='qualification-key', expected_campaign_id='campaign-01')['decision'], 'ALLOW')
    def test_tamper(self):
        e=copy.deepcopy(self.e); e['payload']['decision']='DENY'; self.assertFalse(verify(e,key=KEY,expected_key_id='qualification-key',expected_campaign_id='campaign-01'))
    def test_wrong_key(self): self.assertFalse(verify(self.e,key=b'x'*32,expected_key_id='qualification-key',expected_campaign_id='campaign-01'))
    def test_wrong_campaign(self): self.assertFalse(verify(self.e,key=KEY,expected_key_id='qualification-key',expected_campaign_id='other'))
    def test_stale(self): self.assertFalse(verify(self.e,key=KEY,expected_key_id='qualification-key',expected_campaign_id='campaign-01',now_ns=self.e['payload']['timestamp_ns']+7200*10**9))
    def test_future(self): self.assertFalse(verify(self.e,key=KEY,expected_key_id='qualification-key',expected_campaign_id='campaign-01',now_ns=self.e['payload']['timestamp_ns']-10*10**9))
    def test_bad_identity(self):
        with self.assertRaises(ValueError): collect(self.temp.name,'data',expected_euid=os.geteuid()+100000,**self.kw)
    def test_unsafe_path(self):
        with self.assertRaises(ValueError): collect(self.temp.name,'../data',expected_euid=os.geteuid(),**self.kw)
    def test_weak_key(self):
        with self.assertRaises(ValueError): collect(self.temp.name,'data',expected_euid=os.geteuid(),key=b'weak',key_id='id',campaign_id='campaign')
    def test_no_mutation(self): self.assertEqual(Path(self.temp.name,'data').read_bytes(),b'hello')
    def test_compare(self):
        r=as_comparison_record(self.e,key=KEY,expected_key_id='qualification-key',expected_campaign_id='campaign-01')
        result=compare([r],[r],principal_mapping={r['principal']:r['principal']},source_attested=True,target_attested=True)
        self.assertEqual(result['status'],'MATCH'); self.assertFalse(result['attestation_cryptographically_verified'])

if __name__=='__main__': unittest.main()
