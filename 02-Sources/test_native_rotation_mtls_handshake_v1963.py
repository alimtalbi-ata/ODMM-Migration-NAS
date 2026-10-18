"""Real loopback TLS handshake regression tests; no storage device contacted."""
import http.server
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from native_rotation_mtls import make_mtls_context

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"state":"ok"}')
    def log_message(self, *args):
        pass

class MTLSHandshakeV1963(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        d=Path(cls.tmp.name)
        cls.ca=d/'ca.pem'; cak=d/'ca.key'; cls.server=d/'server.pem'; sk=d/'server.key'; cls.client=d/'client.pem'; ck=d/'client.key'
        def openssl(*args):
            subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',cak,'-out',cls.ca,'-days','1','-subj','/CN=ODMM Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        for label, cert, key, cn in [('server',cls.server,sk,'localhost'),('client',cls.client,ck,'odmm-test-client')]:
            csr=d/(label+'.csr'); ext=d/(label+'.ext')
            ext.write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' if label=='server' else 'extendedKeyUsage=clientAuth\n')
            openssl('req','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj',f'/CN={cn}')
            openssl('x509','-req','-in',csr,'-CA',cls.ca,'-CAkey',cak,'-CAcreateserial','-out',cert,'-days','1','-extfile',ext)
        cls.httpd=http.server.HTTPServer(('127.0.0.1',0),_Handler)
        serverctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        serverctx.load_cert_chain(str(cls.server),str(sk))
        serverctx.load_verify_locations(cafile=str(cls.ca))
        serverctx.verify_mode=ssl.CERT_REQUIRED
        cls.httpd.socket=serverctx.wrap_socket(cls.httpd.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.httpd.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown();cls.httpd.server_close();cls.thread.join(timeout=3);cls.tmp.cleanup()
    def connect(self, ctx):
        import http.client
        c=http.client.HTTPSConnection('localhost',self.httpd.server_port,context=ctx,timeout=2)
        try:
            c.request('GET','/');r=c.getresponse();return r.status,r.read()
        finally:c.close()
    def test_real_mtls_handshake_and_json(self):
        ctx=make_mtls_context(ca_file=self.ca,certificate_file=self.client,private_key_file=self.client.with_suffix('.key'))
        self.assertEqual(self.connect(ctx),(200,b'{"state":"ok"}'))
    def test_no_client_certificate_rejected(self):
        ctx=ssl.create_default_context(cafile=str(self.ca))
        with self.assertRaises((ssl.SSLError,ConnectionError,OSError)):
            self.connect(ctx)
    def test_untrusted_ca_rejected(self):
        ctx=ssl.create_default_context()
        ctx.load_cert_chain(str(self.client),str(self.client.with_suffix('.key')))
        with self.assertRaises(ssl.SSLError):self.connect(ctx)
    def test_hostname_mismatch_rejected(self):
        ctx=make_mtls_context(ca_file=self.ca,certificate_file=self.client,private_key_file=self.client.with_suffix('.key'))
        import socket
        with socket.create_connection(('127.0.0.1',self.httpd.server_port),timeout=2) as sock:
            with self.assertRaises(ssl.SSLCertVerificationError):
                with ctx.wrap_socket(sock,server_hostname='wrong.example'):pass

if __name__=='__main__':unittest.main()
