import ssl
import unittest
from native_rotation_https_transport import make_https_get_transport, TransportRejected

class Response:
    status=200
    def __init__(self, content_type='application/json', data=b'{}'):
        self.content_type=content_type; self.data=data
    def getheader(self,name): return self.content_type if name=='Content-Type' else None
    def read(self,n): return self.data[:n]
class Connection:
    def __init__(self, response): self.response=response; self.closed=False
    def request(self,*args,**kwargs): pass
    def getresponse(self): return self.response
    def close(self): self.closed=True
class PolicyTests(unittest.TestCase):
    def setUp(self): self.ctx=ssl.create_default_context(); self.conn=Connection(Response())
    def build(self,**kw):
        return make_https_get_transport(approved_origins=['https://array.example'],ssl_context=self.ctx,connection_factory=lambda *a:self.conn,**kw)
    def test_json_ok(self): self.assertEqual(self.build(require_json=True)('https://array.example/x',{})[0],200)
    def test_vendor_json_ok(self):
        self.conn=Connection(Response('application/problem+json'))
        self.assertEqual(self.build(require_json=True)('https://array.example/x',{})[0],200)
    def test_html_rejected(self):
        self.conn=Connection(Response('text/html'))
        with self.assertRaises(TransportRejected): self.build(require_json=True)('https://array.example/x',{})
        self.assertTrue(self.conn.closed)
    def test_missing_content_type_rejected(self):
        self.conn=Connection(Response(None))
        with self.assertRaises(TransportRejected): self.build(require_json=True)('https://array.example/x',{})
    def test_no_attestor_fails_closed(self):
        with self.assertRaises(TransportRejected): self.build(require_client_certificate=True)
    def test_false_attestor_fails_closed(self):
        with self.assertRaises(TransportRejected): self.build(require_client_certificate=True,client_certificate_attestor=lambda ctx:False)
    def test_true_attestor(self):
        get=self.build(require_client_certificate=True,client_certificate_attestor=lambda ctx:True)
        self.assertEqual(get('https://array.example/x',{})[0],200)
    def test_attestor_exception_fails_closed(self):
        def bad(ctx): raise RuntimeError('unavailable')
        with self.assertRaises(RuntimeError): self.build(require_client_certificate=True,client_certificate_attestor=bad)
    def test_invalid_policy_type(self):
        with self.assertRaises(TransportRejected): self.build(require_json='yes')
    def test_client_identity_policy_type(self):
        with self.assertRaises(TransportRejected): self.build(require_client_certificate=1)
