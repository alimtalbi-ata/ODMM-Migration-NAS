"""Real loopback mTLS integration tests with ephemeral OpenSSL test CA."""
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from ldaps_remote_witness import RemoteWitnessVerifier
from ldaps_remote_witness_server import RemoteWitnessStore, make_mtls_server, ZERO
from ldaps_ipc_persistent_identity import IdentityPinError

KEY=b'W'*32

@unittest.skipUnless(shutil.which('openssl'), 'openssl executable required')
class MutualTLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        def run(*args):
            subprocess.run(['openssl',*args],cwd=cls.root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=15)
        run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.crt','-days','1','-subj','/CN=ODMM Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        for role in ('server','client','rogue'):
            run('req','-newkey','rsa:2048','-nodes','-keyout',f'{role}.key','-out',f'{role}.csr','-subj',f'/CN={role}')
            ext=cls.root/f'{role}.ext'
            ext.write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' if role=='server' else 'extendedKeyUsage=clientAuth\n')
            run('x509','-req','-in',f'{role}.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',f'{role}.crt','-days','1','-extfile',str(ext))
        run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','other.key','-out','other.crt','-days','1','-subj','/CN=Untrusted')
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def setUp(self):
        self.db=tempfile.TemporaryDirectory()
        self.store=RemoteWitnessStore(Path(self.db.name)/'store.sqlite',key=KEY)
        self.server=make_mtls_server(host='127.0.0.1',port=0,store=self.store,certfile=str(self.root/'server.crt'),keyfile=str(self.root/'server.key'),cafile=str(self.root/'ca.crt'))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3);self.db.cleanup()
    def client(self, **overrides):
        options=dict(host='127.0.0.1',port=self.server.server_address[1],cafile=str(self.root/'ca.crt'),certfile=str(self.root/'client.crt'),keyfile=str(self.root/'client.key'),witness_key=KEY,timeout=1)
        options.update(overrides)
        return RemoteWitnessVerifier(**options)
    def test_real_mtls_success(self):
        self.assertEqual(self.client().verify(expected_count=0,expected_last_mac=ZERO)['status'],'REMOTE_WITNESS_VERIFIED')
    def test_real_mtls_after_publication(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac='a'*64,operator_confirmed=True)
        self.assertEqual(self.client().verify(expected_count=1,expected_last_mac='a'*64)['count'],1)
    def test_wrong_server_ca_fails_closed(self):
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):
            self.client(cafile=str(self.root/'other.crt')).verify(expected_count=0,expected_last_mac=ZERO)
    def test_wrong_server_name_fails_closed(self):
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):
            self.client(server_name='untrusted.invalid').verify(expected_count=0,expected_last_mac=ZERO)
    def test_client_without_certificate_fails_closed(self):
        import ssl
        ctx=ssl.create_default_context(cafile=str(self.root/'ca.crt'))
        with self.assertRaises((ssl.SSLError,OSError,EOFError)):
            with socket.create_connection(self.server.server_address,timeout=2) as raw:
                with ctx.wrap_socket(raw,server_hostname='localhost') as conn:
                    conn.sendall(b'{"version":1,"action":"read","nonce":"'+b'a'*64+b'"}\n')
                    if not conn.recv(4096): raise EOFError('server refused unauthenticated client')
    def test_divergent_remote_state_fails_closed(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac='b'*64,operator_confirmed=True)
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):
            self.client().verify(expected_count=0,expected_last_mac=ZERO)
    def test_bad_witness_hmac_fails_closed(self):
        with self.assertRaisesRegex(IdentityPinError,'AUTH_FAILED'):
            self.client(witness_key=b'Z'*32).verify(expected_count=0,expected_last_mac=ZERO)
    def test_unavailable_after_shutdown(self):
        port=self.server.server_address[1]
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):
            self.client(port=port,timeout=.2).verify(expected_count=0,expected_last_mac=ZERO)

if __name__=='__main__': unittest.main()
