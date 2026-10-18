"""V188.1 real TLS socket restart and outage regression scenarios."""
import socket
import threading
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_remote_witness_server import RemoteWitnessStore, make_mtls_server, ZERO
import test_ldaps_remote_witness_mtls_e2e as baseline
KEY = baseline.KEY
MutualTLSIntegrationTests = baseline.MutualTLSIntegrationTests

class RestartNetworkTests(unittest.TestCase):
    setUpClass = classmethod(lambda cls: MutualTLSIntegrationTests.setUpClass.__func__(cls))
    tearDownClass = classmethod(lambda cls: MutualTLSIntegrationTests.tearDownClass.__func__(cls))
    setUp = MutualTLSIntegrationTests.setUp
    tearDown = MutualTLSIntegrationTests.tearDown
    client = MutualTLSIntegrationTests.client

    def restart(self):
        port=self.server.server_address[1]
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
        self.store=RemoteWitnessStore(Path(self.db.name)/'store.sqlite',key=KEY)
        self.server=make_mtls_server(host='127.0.0.1',port=port,store=self.store,
            certfile=str(self.root/'server.crt'),keyfile=str(self.root/'server.key'),cafile=str(self.root/'ca.crt'))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def test_empty_state_survives_restart(self):
        self.restart()
        self.assertEqual(self.client().verify(expected_count=0,expected_last_mac=ZERO)['count'],0)

    def test_published_state_survives_restart(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac='a'*64,operator_confirmed=True)
        self.restart()
        self.assertEqual(self.client().verify(expected_count=1,expected_last_mac='a'*64)['count'],1)

    def test_old_state_rejected_after_restart(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac='a'*64,operator_confirmed=True)
        self.restart()
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):
            self.client().verify(expected_count=0,expected_last_mac=ZERO)

    def test_outage_then_restart_recovers(self):
        port=self.server.server_address[1]
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):
            self.client(port=port,timeout=.2).verify(expected_count=0,expected_last_mac=ZERO)
        self.store=RemoteWitnessStore(Path(self.db.name)/'store.sqlite',key=KEY)
        self.server=make_mtls_server(host='127.0.0.1',port=port,store=self.store,
            certfile=str(self.root/'server.crt'),keyfile=str(self.root/'server.key'),cafile=str(self.root/'ca.crt'))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.assertEqual(self.client().verify(expected_count=0,expected_last_mac=ZERO)['count'],0)

    def test_wrong_key_still_fails_after_restart(self):
        self.restart()
        with self.assertRaisesRegex(IdentityPinError,'AUTH_FAILED'):
            self.client(witness_key=b'X'*32).verify(expected_count=0,expected_last_mac=ZERO)

    def test_publication_is_not_network_exposed(self):
        self.restart()
        import ssl,json
        ctx=ssl.create_default_context(cafile=str(self.root/'ca.crt'))
        ctx.load_cert_chain(str(self.root/'client.crt'),str(self.root/'client.key'))
        with socket.create_connection(self.server.server_address,timeout=2) as raw:
            with ctx.wrap_socket(raw,server_hostname='localhost') as conn:
                conn.settimeout(2)
                conn.sendall((json.dumps({'version':1,'action':'publish','nonce':'a'*64})+'\n').encode())
                self.assertEqual(conn.recv(100),b'')
        self.assertEqual(self.store.read(),(0,ZERO))

    def test_two_entries_persist(self):
        self.store.publish(expected_count=0,expected_last_mac=ZERO,new_count=1,new_last_mac='a'*64,operator_confirmed=True)
        self.store.publish(expected_count=1,expected_last_mac='a'*64,new_count=2,new_last_mac='b'*64,operator_confirmed=True)
        self.restart()
        self.assertEqual(self.client().verify(expected_count=2,expected_last_mac='b'*64)['count'],2)

if __name__=='__main__': unittest.main()
