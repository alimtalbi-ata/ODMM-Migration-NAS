import ssl
import unittest
from native_rotation_https_transport import make_https_get_transport, TransportRejected

class Response:
    status=200
    def __init__(self, data=b'{}', length=None, status=200):
        self.data=data; self.length=length; self.status=status
    def getheader(self, name): return self.length if name=='Content-Length' else None
    def read(self, n): return self.data[:n]

class Conn:
    def __init__(self, response): self.response=response; self.closed=False; self.calls=[]
    def request(self,*a,**kw): self.calls.append((a,kw))
    def getresponse(self): return self.response
    def close(self): self.closed=True

class TransportTests(unittest.TestCase):
    def setUp(self):
        self.ctx=ssl.create_default_context()
        self.conn=Conn(Response())
    def transport(self, **kw):
        return make_https_get_transport(approved_origins=kw.get('origins', ['https://array.example']),
          ssl_context=kw.get('ctx',self.ctx), timeout=kw.get('timeout',5),
          max_response_bytes=kw.get('limit',65536),
          connection_factory=lambda *args:self.conn)
    def test_get_only(self):
        self.assertEqual(self.transport()('https://array.example/api/vol?x=1',{})[0],200)
        self.assertEqual(self.conn.calls[0][0],('GET','/api/vol?x=1'))
        self.assertTrue(self.conn.closed)
    def test_cross_origin(self):
        with self.assertRaises(TransportRejected): self.transport()('https://other.example/',{})
    def test_http_rejected(self):
        with self.assertRaises(TransportRejected): self.transport()('http://array.example/',{})
    def test_userinfo_rejected(self):
        with self.assertRaises(TransportRejected): self.transport()('https://user@array.example/',{})
    def test_ip_rejected(self):
        with self.assertRaises(TransportRejected): self.transport(origins=['https://127.0.0.1'])
    def test_redirect_rejected(self):
        self.conn=Conn(Response(status=302))
        with self.assertRaises(TransportRejected): self.transport()('https://array.example/',{})
        self.assertTrue(self.conn.closed)
    def test_size_rejected(self):
        self.conn=Conn(Response(data=b'a'*11))
        with self.assertRaises(TransportRejected): self.transport(limit=10)('https://array.example/',{})
    def test_declared_size_rejected(self):
        self.conn=Conn(Response(length='100'))
        with self.assertRaises(TransportRejected): self.transport(limit=10)('https://array.example/',{})
    def test_header_injection(self):
        with self.assertRaises(TransportRejected): self.transport()('https://array.example/',{'X':'x\r\ny'})
    def test_host_override(self):
        with self.assertRaises(TransportRejected): self.transport()('https://array.example/',{'Host':'evil'})
    def test_tls_required(self):
        ctx=ssl._create_unverified_context()
        with self.assertRaises(TransportRejected): self.transport(ctx=ctx)
    def test_timeout_bound(self):
        with self.assertRaises(TransportRejected): self.transport(timeout=60)
    def test_bad_content_length(self):
        self.conn=Conn(Response(length='abc'))
        with self.assertRaises(TransportRejected): self.transport()('https://array.example/',{})
    def test_fragment_rejected(self):
        with self.assertRaises(TransportRejected): self.transport()('https://array.example/#x',{})

if __name__=='__main__': unittest.main()
