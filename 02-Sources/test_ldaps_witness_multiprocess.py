"""V188.2: independent-process SQLite and real mTLS restart qualification."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from ldaps_remote_witness_server import RemoteWitnessStore, ZERO
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_remote_witness import RemoteWitnessVerifier
from test_ldaps_remote_witness_mtls_e2e import MutualTLSIntegrationTests, KEY

PUBLISH = '''import sys,json
from ldaps_remote_witness_server import RemoteWitnessStore
p,expected,head,new,mac=sys.argv[1:]
s=RemoteWitnessStore(p,key=b'W'*32)
try:
 print(json.dumps(s.publish(expected_count=int(expected),expected_last_mac=head,new_count=int(new),new_last_mac=mac,operator_confirmed=True)))
except Exception as e:
 print(json.dumps({'error':str(e)}))
'''
SERVER = '''import sys,json,signal
from ldaps_remote_witness_server import RemoteWitnessStore,make_mtls_server
p,cert,key,ca=sys.argv[1:]
s=make_mtls_server(host='127.0.0.1',port=0,store=RemoteWitnessStore(p,key=b'W'*32),certfile=cert,keyfile=key,cafile=ca)
print(json.dumps({'port':s.server_address[1]}),flush=True)
try:s.serve_forever()
finally:s.server_close()
'''

class MultiprocessWitnessTests(unittest.TestCase):
    setUpClass = classmethod(lambda cls: MutualTLSIntegrationTests.setUpClass.__func__(cls))
    tearDownClass = classmethod(lambda cls: MutualTLSIntegrationTests.tearDownClass.__func__(cls))

    def setUp(self):
        self.tempdb=tempfile.TemporaryDirectory()
        self.path=str(Path(self.tempdb.name)/'witness.sqlite')
        self.store=RemoteWitnessStore(self.path,key=KEY)
        self.children=[]
    def tearDown(self):
        for p in self.children:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
            if p.stdout:p.stdout.close()
            if p.stderr:p.stderr.close()
        self.tempdb.cleanup()
    def child(self,script,*args):
        return subprocess.Popen([sys.executable,'-c',script,*map(str,args)],cwd=str(Path(__file__).parent),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def publish(self,expected,new,head='a'*64):
        p=self.child(PUBLISH,self.path,expected,ZERO,new,head)
        out,err=p.communicate(timeout=8)
        self.assertEqual(p.returncode,0,err)
        return json.loads(out)
    def start_server(self):
        p=self.child(SERVER,self.path,self.root/'server.crt',self.root/'server.key',self.root/'ca.crt')
        self.children.append(p)
        # readiness: child prints bound port only after successful TLS initialization
        import select
        ready,_,_=select.select([p.stdout],[],[],5)
        self.assertTrue(ready,'server process did not become ready')
        line=p.stdout.readline()
        self.assertTrue(line, 'server process exited')
        return p,json.loads(line)['port']
    def verifier(self,port):
        return RemoteWitnessVerifier(host='127.0.0.1',port=port,cafile=str(self.root/'ca.crt'),certfile=str(self.root/'client.crt'),keyfile=str(self.root/'client.key'),witness_key=KEY,timeout=.5)
    def test_publication_survives_process_exit(self):
        self.assertEqual(self.publish(0,1)['count'],1)
        self.assertEqual(RemoteWitnessStore(self.path,key=KEY).read(),(1,'a'*64))
    def test_concurrent_publication_only_one_commits(self):
        children=[self.child(PUBLISH,self.path,0,ZERO,1,'a'*64) for _ in range(6)]
        results=[]
        for p in children:
            out,err=p.communicate(timeout=10)
            self.assertEqual(p.returncode,0,err)
            results.append(json.loads(out))
        self.assertEqual(sum('count' in r for r in results),1)
        self.assertTrue(all('STALE' in r['error'] for r in results if 'error' in r))
        self.assertEqual(self.store.read(),(1,'a'*64))
    def test_two_independent_processes_serialized(self):
        self.assertEqual(self.publish(0,1)['count'],1)
        p=self.child(PUBLISH,self.path,1,'a'*64,2,'b'*64)
        out,err=p.communicate(timeout=8)
        self.assertEqual(p.returncode,0,err)
        self.assertEqual(json.loads(out)['count'],2)
        self.assertEqual(self.store.read(),(2,'b'*64))
    def test_real_tls_child_process_restart_persists(self):
        p,port=self.start_server()
        self.assertEqual(self.verifier(port).verify(expected_count=0,expected_last_mac=ZERO)['count'],0)
        p.terminate();p.wait(timeout=3)
        self.assertEqual(self.publish(0,1)['count'],1)
        p2,port2=self.start_server()
        self.assertEqual(self.verifier(port2).verify(expected_count=1,expected_last_mac='a'*64)['count'],1)
    def test_killed_server_fails_closed(self):
        p,port=self.start_server()
        self.assertEqual(self.verifier(port).verify(expected_count=0,expected_last_mac=ZERO)['count'],0)
        p.kill();p.wait(timeout=3)
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):
            self.verifier(port).verify(expected_count=0,expected_last_mac=ZERO)
    def test_stale_client_after_restart_fails_closed(self):
        self.assertEqual(self.publish(0,1)['count'],1)
        p,port=self.start_server()
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):
            self.verifier(port).verify(expected_count=0,expected_last_mac=ZERO)
    def test_corrupt_database_rejected_in_new_process(self):
        self.assertEqual(self.publish(0,1)['count'],1)
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE witness SET last_mac=? WHERE seq=1",('f'*64,))
        p=self.child(PUBLISH,self.path,1,'a'*64,2,'b'*64)
        out,err=p.communicate(timeout=8)
        self.assertEqual(p.returncode,0,err)
        self.assertIn('LEDGER_INVALID',json.loads(out)['error'])

if __name__=='__main__': unittest.main()
