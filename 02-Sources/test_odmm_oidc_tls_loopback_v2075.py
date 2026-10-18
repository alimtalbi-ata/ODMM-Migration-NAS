"""Real TCP/TLS loopback tests, not a production identity provider. Author: Abdelhalim Talbi."""
import datetime, ipaddress, json, ssl, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from odmm_oidc_https_v2070 import StrictOIDCHTTP, make_trusted_oidc
from odmm_oidc_pkce_v2068 import OIDCVerificationError

@contextmanager
def tls_server(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
      .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=1))
      .not_valid_after(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=1))
      .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
      .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    crt=tmp_path/'ca.pem'; pem=tmp_path/'key.pem'
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            issuer=f'https://localhost:{self.server.server_port}'
            if self.path=='/.well-known/openid-configuration':
                body=json.dumps({'issuer':issuer,'authorization_endpoint':issuer+'/authorize','token_endpoint':issuer+'/token','jwks_uri':issuer+'/jwks'}).encode()
            elif self.path=='/jwks':body=b'{"keys":[]}'
            elif self.path=='/redirect':
                self.send_response(302);self.send_header('Location',issuer+'/jwks');self.end_headers();return
            elif self.path=='/oversize':body=b'{"data":"'+b'x'*140000+b'"}'
            else:body=b'{}'
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def do_POST(self):
            length=int(self.headers.get('Content-Length','0'));self.rfile.read(length)
            body=b'{"id_token":"signed-in-test-only"}'
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(crt),str(pem))
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield f'https://localhost:{server.server_port}',str(crt)
    finally:server.shutdown();server.server_close();thread.join(timeout=5)

def test_private_ca_verified_real_tls(tmp_path):
    with tls_server(tmp_path) as (issuer,ca):
        transport,client=make_trusted_oidc(issuer=issuer,client_id='odmm',ca_file=ca)
        try:
            assert transport.discovery()['issuer']==issuer
            assert transport.jwks()=={'keys':[]}
            assert transport.exchange(code='abc',verifier='v'*43,redirect_uri='https://odmm.example/callback')=='signed-in-test-only'
        finally:client.close()

def test_untrusted_certificate_rejected(tmp_path):
    with tls_server(tmp_path) as (issuer,ca):
        client=StrictOIDCHTTP(issuer=issuer)
        try:
            with pytest.raises(Exception) as exc:client.get(issuer+'/jwks')
            assert 'certificate' in str(exc.value).lower() or 'verify' in str(exc.value).lower()
        finally:client.close()

def test_redirect_and_oversize_fail_closed(tmp_path):
    with tls_server(tmp_path) as (issuer,ca):
        client=StrictOIDCHTTP(issuer=issuer,ca_file=ca)
        try:
            with pytest.raises(OIDCVerificationError,match='OIDC_HTTP_STATUS'):client.get(issuer+'/redirect')
            with pytest.raises(OIDCVerificationError,match='OIDC_RESPONSE_TOO_LARGE'):client.get(issuer+'/oversize')
        finally:client.close()

def test_endpoint_origin_pinning_real_tls(tmp_path):
    with tls_server(tmp_path) as (issuer,ca):
        client=StrictOIDCHTTP(issuer=issuer,ca_file=ca)
        try:
            with pytest.raises(OIDCVerificationError,match='UNTRUSTED_ENDPOINT'):client.get('https://example.org/jwks')
        finally:client.close()
