import copy
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from odmm_access_attestation_v2027 import collect
from odmm_integrated_registry_v2030 import IntegratedRegistry
from odmm_registry_resilience_v2031 import export,verify_export,snapshot

class ResilienceTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name);self.p=self.root/'registry.db';self.r=IntegratedRegistry(self.p)
        self.r.create('campaign',['nas']);self.root.joinpath('src').mkdir();self.root.joinpath('dst').mkdir()
        for side in ('src','dst'):(self.root/side/'f').write_text('unchanged')
    def add(self,side):
        key=side.encode()*32
        env=collect(str(self.root/side),'f',expected_euid=os.geteuid(),key=key,key_id=side,campaign_id='campaign')
        return self.r.ingest('campaign','nas','source' if side=='src' else 'target',env,key=key,key_id=side)
    def both(self):self.add('src');self.add('dst')
    def test_empty(self):self.assertTrue(verify_export(export(self.p)))
    def test_full(self):self.both();self.assertTrue(verify_export(export(self.p)))
    def test_snapshot(self):
        self.both();report=snapshot(self.p,self.root/'copy.db');self.assertTrue(verify_export(report));self.assertEqual(report,export(self.root/'copy.db'))
    def test_existing_destination(self):
        with self.assertRaisesRegex(ValueError,'DESTINATION_EXISTS'):snapshot(self.p,self.p)
    def test_missing(self):
        with self.assertRaisesRegex(ValueError,'REGISTRY_MISSING'):export(self.root/'absent')
    def test_hash_tamper(self):
        self.both();r=export(self.p);r['counts']['audit_chain']=4;self.assertFalse(verify_export(r))
    def test_rehashed_tamper(self):
        from odmm_campaign_registry_v2029 import digest
        self.both();r=export(self.p);r['tables']['audit_chain'][0][2]='{}';r['report_sha256']=digest({k:v for k,v in r.items() if k!='report_sha256'});self.assertFalse(verify_export(r))
    def test_sequence_gap(self):
        self.both()
        with sqlite3.connect(self.p) as db:db.execute('UPDATE audit_chain SET seq=8 WHERE seq=2')
        with self.assertRaisesRegex(ValueError,'AUDIT_SEQUENCE_BROKEN'):export(self.p)
    def test_orphan_observation(self):
        self.both()
        with sqlite3.connect(self.p) as db:db.execute("DELETE FROM observations WHERE side='target'")
        with self.assertRaisesRegex(ValueError,'DIVERGENCE'):export(self.p)
    def test_corrupted_envelope(self):
        self.both()
        with sqlite3.connect(self.p) as db:db.execute("UPDATE signed_evidence SET envelope='{}' WHERE side='target'")
        with self.assertRaisesRegex(ValueError,'ENVELOPE_DIGEST_MISMATCH'):export(self.p)
    def test_idempotent_restart(self):
        key=b'src'*32;env=collect(str(self.root/'src'),'f',expected_euid=os.geteuid(),key=key,key_id='src',campaign_id='campaign');self.assertTrue(self.r.ingest('campaign','nas','source',env,key=key,key_id='src'));self.r=IntegratedRegistry(self.p);self.assertFalse(self.r.ingest('campaign','nas','source',env,key=key,key_id='src'));self.add('dst');self.assertTrue(verify_export(export(self.p)))
    def test_concurrent_idempotent(self):
        errors=[];results=[]
        def worker():
            try:results.append(self.add('src'))
            except Exception as e:errors.append(str(e))
        threads=[threading.Thread(target=worker) for _ in range(4)]
        for t in threads:t.start()
        for t in threads:t.join()
        # Freshly collected signed envelopes have unique timestamps: one wins, others conflict.
        self.assertEqual(results.count(True),1);self.assertEqual(len(errors),3)
        self.assertTrue(verify_export(export(self.p)))
    def test_no_nas_write(self):
        self.both();snapshot(self.p,self.root/'backup.db')
        for side in ('src','dst'):self.assertEqual((self.root/side/'f').read_text(),'unchanged')

if __name__=='__main__':unittest.main()
