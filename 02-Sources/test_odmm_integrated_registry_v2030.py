import copy
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_access_attestation_v2027 import collect
from odmm_integrated_registry_v2030 import IntegratedRegistry, verify_report

class IntegratedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name); self.src=root/'src';self.dst=root/'dst';self.src.mkdir();self.dst.mkdir()
        (self.src/'f').write_text('hello');(self.dst/'f').write_text('hello')
        self.path=root/'audit.sqlite';self.r=IntegratedRegistry(self.path);self.r.create('campaign',['nas'])
        self.skey=b's'*32;self.tkey=b't'*32
        self.s=collect(str(self.src),'f',expected_euid=os.geteuid(),key=self.skey,key_id='source',campaign_id='campaign')
        self.t=collect(str(self.dst),'f',expected_euid=os.geteuid(),key=self.tkey,key_id='target',campaign_id='campaign')
    def ingest(self,side='source',envelope=None):
        return self.r.ingest('campaign','nas',side,envelope or (self.s if side=='source' else self.t),key=self.skey if side=='source' else self.tkey,key_id=side)
    def qualify(self):
        p='UID:'+str(os.geteuid())
        return self.r.qualify('campaign','nas',source_key=self.skey,target_key=self.tkey,source_key_id='source',target_key_id='target',principal_mapping={p:p})
    def test_match(self):
        self.ingest();self.ingest('target');r=self.qualify();self.assertEqual(r['status'],'MATCH');self.assertTrue(verify_report(r))
    def test_idempotent(self):
        self.assertTrue(self.ingest());self.assertFalse(self.ingest())
    def test_resume(self):
        self.ingest();self.r=IntegratedRegistry(self.path);self.ingest('target');self.assertEqual(self.qualify()['status'],'MATCH')
    def test_partial(self):
        self.ingest();self.assertEqual(self.qualify()['status'],'UNVERIFIED')
    def test_tamper(self):
        e=copy.deepcopy(self.s);e['payload']['decision']='DENY'
        with self.assertRaisesRegex(ValueError,'INVALID_ATTESTATION'):self.ingest(envelope=e)
    def test_replay(self):
        self.ingest()
        with self.assertRaisesRegex(ValueError,'REPLAYED'):self.r.ingest('campaign','nas','target',self.s,key=self.skey,key_id='source')
    def test_conflict(self):
        self.ingest();e=collect(str(self.src),'f',expected_euid=os.geteuid(),key=self.skey,key_id='source',campaign_id='campaign')
        with self.assertRaisesRegex(ValueError,'CONFLICTING'):self.ingest(envelope=e)
    def test_audit(self):
        self.ingest();self.ingest('target');self.assertEqual(self.r.audit()['events'],2)
    def test_chain_tamper(self):
        self.ingest()
        with sqlite3.connect(self.path) as db:db.execute("UPDATE audit_chain SET event_json='{}'")
        with self.assertRaisesRegex(ValueError,'AUDIT_CHAIN_BROKEN'):self.r.audit()
    def test_report_tamper(self):
        self.ingest();self.ingest('target');r=self.qualify();r['status']='MISMATCH';self.assertFalse(verify_report(r))
    def test_no_nas_write(self):
        self.ingest();self.ingest('target');self.assertEqual((self.src/'f').read_text(),'hello');self.assertEqual((self.dst/'f').read_text(),'hello')
    def test_registry_report(self):
        self.ingest();self.ingest('target');self.assertEqual(self.r.report('campaign')['status'],'COMPLETE')

if __name__=='__main__':unittest.main()
