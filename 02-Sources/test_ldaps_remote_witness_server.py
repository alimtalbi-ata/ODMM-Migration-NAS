import hashlib
import hmac
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from ldaps_remote_witness import RemoteWitnessVerifier
from ldaps_remote_witness_server import RemoteWitnessStore, ZERO
from ldaps_ipc_persistent_identity import IdentityPinError

KEY=b'W'*32
A='a'*64
B='b'*64
class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'witness.sqlite'
        self.store=RemoteWitnessStore(self.path,key=KEY)
    def tearDown(self): self.tmp.cleanup()
    def test_empty_read(self): self.assertEqual(self.store.read(),(0,ZERO))
    def test_read_compatible_with_client(self):
        c=RemoteWitnessVerifier(host='example.org',port=443,cafile='ca',certfile='cert',keyfile='key',witness_key=KEY,transport=self.store.handle_read)
        self.assertEqual(c.verify(expected_count=0,expected_last_mac=ZERO)['status'],'REMOTE_WITNESS_VERIFIED')
    def test_publish_then_read(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=True)
        self.assertEqual(self.store.read(),(1,A))
    def test_restart(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=True)
        self.assertEqual(RemoteWitnessStore(self.path,key=KEY).read(),(1,A))
    def test_no_operator_confirmation(self):
        with self.assertRaisesRegex(IdentityPinError,'CONFIRMATION'):
            self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=False)
    def test_stale_publication(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=True)
        with self.assertRaisesRegex(IdentityPinError,'STALE'):
            self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=2,new_last_mac=B,operator_confirmed=True)
    def test_replay_count(self):
        with self.assertRaisesRegex(IdentityPinError,'INVALID'):
            self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=0,new_last_mac=A,operator_confirmed=True)
    def test_tamper(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=True)
        with sqlite3.connect(self.path) as db: db.execute('UPDATE witness SET last_mac=?',(B,))
        with self.assertRaisesRegex(IdentityPinError,'LEDGER_INVALID'): self.store.read()
    def test_wrong_key(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=True)
        with self.assertRaisesRegex(IdentityPinError,'LEDGER_INVALID'):
            RemoteWitnessStore(self.path,key=b'X'*32).read()
    def test_malformed_request(self):
        with self.assertRaisesRegex(IdentityPinError,'REQUEST_INVALID'):
            self.store.handle_read({'version':1,'action':'publish','nonce':'f'*64})
    def test_bad_nonce(self):
        with self.assertRaisesRegex(IdentityPinError,'REQUEST_INVALID'):
            self.store.handle_read({'version':1,'action':'read','nonce':'oops'})
    def test_concurrent_writers_one_wins(self):
        barrier=threading.Barrier(2)
        results=[]
        def worker(head):
            barrier.wait()
            try:
                self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=head,operator_confirmed=True)
                results.append('ok')
            except IdentityPinError: results.append('stale')
        t1=threading.Thread(target=worker,args=(A,));t2=threading.Thread(target=worker,args=(B,))
        t1.start();t2.start();t1.join();t2.join()
        self.assertCountEqual(results,['ok','stale'])
    def test_recovery_after_exception(self):
        with self.assertRaisesRegex(IdentityPinError,'INVALID'):
            self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=-1,new_last_mac=A,operator_confirmed=True)
        self.assertEqual(self.store.read(),(0,ZERO))
    def test_second_append(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac=A,operator_confirmed=True)
        self.store.publish(expected_count=1,expected_last_mac=A,new_count=2,new_last_mac=B,operator_confirmed=True)
        self.assertEqual(self.store.read(),(2,B))
if __name__=='__main__':unittest.main()
