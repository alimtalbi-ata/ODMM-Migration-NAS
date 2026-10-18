import ssl
import unittest
from unittest.mock import patch
from native_rotation_mtls import make_mtls_context, make_mtls_vendor_get, MTLSConfigurationRejected
from native_rotation_https_transport import TransportRejected

class MTLSV1962Tests(unittest.TestCase):
    def test_missing_material_rejected(self):
        with self.assertRaises(MTLSConfigurationRejected):
            make_mtls_context(ca_file='/missing-ca', certificate_file='/missing-cert', private_key_file='/missing-key')
    def test_empty_path_rejected(self):
        with self.assertRaises(MTLSConfigurationRejected):
            make_mtls_context(ca_file='', certificate_file='cert', private_key_file='key')
    def test_null_path_rejected(self):
        with self.assertRaises(MTLSConfigurationRejected):
            make_mtls_context(ca_file='ca', certificate_file='a\x00b', private_key_file='key')
    def test_minimum_tls_rejected(self):
        with self.assertRaises(MTLSConfigurationRejected):
            make_mtls_context(ca_file='ca', certificate_file='cert', private_key_file='key', minimum_version=ssl.TLSVersion.TLSv1_1)
    def test_valid_context_config(self):
        ctx=ssl.create_default_context()
        with patch('native_rotation_mtls.ssl.create_default_context', return_value=ctx) as create, patch.object(ctx,'load_cert_chain') as load:
            out=make_mtls_context(ca_file='ca',certificate_file='cert',private_key_file='key')
        self.assertIs(out,ctx); self.assertTrue(out.check_hostname)
        self.assertEqual(out.verify_mode,ssl.CERT_REQUIRED)
        self.assertEqual(out.minimum_version,ssl.TLSVersion.TLSv1_2)
        load.assert_called_once_with(certfile='cert',keyfile='key')
    def test_invalid_cert_pair_fails_closed(self):
        ctx=ssl.create_default_context()
        with patch('native_rotation_mtls.ssl.create_default_context',return_value=ctx), patch.object(ctx,'load_cert_chain',side_effect=ssl.SSLError('invalid')):
            with self.assertRaises(MTLSConfigurationRejected):
                make_mtls_context(ca_file='ca',certificate_file='cert',private_key_file='key')
    def test_client_identity_loaded_before_get(self):
        ctx=ssl.create_default_context()
        with patch('native_rotation_mtls.make_mtls_context',return_value=ctx):
            transport=make_mtls_vendor_get(approved_origins=['https://array.example'],ca_file='ca',certificate_file='cert',private_key_file='key')
        with self.assertRaises(TransportRejected): transport('http://array.example/api',{})
    def test_json_required_in_mtls_transport(self):
        ctx=ssl.create_default_context()
        class Response:
            status=200
            def getheader(self,n): return 'text/plain' if n=='Content-Type' else None
            def read(self,n): return b'{}'
        class Conn:
            def request(self,*args,**kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        with patch('native_rotation_mtls.make_mtls_context',return_value=ctx):
            transport=make_mtls_vendor_get(approved_origins=['https://array.example'],ca_file='ca',certificate_file='cert',private_key_file='key',connection_factory=lambda *a:Conn())
        with self.assertRaises(TransportRejected): transport('https://array.example/api',{})

if __name__=='__main__': unittest.main()
