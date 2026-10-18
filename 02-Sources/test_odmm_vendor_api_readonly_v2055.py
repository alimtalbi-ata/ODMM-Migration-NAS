import unittest, io
from odmm_vendor_api_readonly_v2055 import collect,CollectorConfig,CollectionError
class Response:
    status=200
    headers={'Content-Type':'application/json'}
    def __init__(self,data=b'{"version":"9.1"}'):self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def read(self,n):return self.data[:n]
class Opener:
    def __init__(self,response=None):self.response=response or Response()
    def open(self,req,timeout):
        assert req.get_method()=='GET'
        assert req.full_url.startswith('https://')
        return self.response
class Tests(unittest.TestCase):
    def cfg(self,**kw):return CollectorConfig(**({'vendor':'netapp_ontap','host':'nas.example','token':'test','allow_hosts':('nas.example',)}|kw))
    def test_get(self):
        r=collect(self.cfg(),Opener());self.assertEqual(r['status'],'UNVERIFIED');self.assertFalse(r['cutover_authorized'])
    def test_host_allowlist(self):
        with self.assertRaises(CollectionError):collect(self.cfg(allow_hosts=()),Opener())
    def test_vendor(self):
        with self.assertRaises(CollectionError):collect(self.cfg(vendor='other'),Opener())
    def test_invalid_host(self):
        with self.assertRaises(CollectionError):collect(self.cfg(host='a/path'),Opener())
    def test_bad_timeout(self):
        with self.assertRaises(CollectionError):collect(self.cfg(timeout=60),Opener())
    def test_size_limit(self):
        with self.assertRaises(CollectionError):collect(self.cfg(),Opener(Response(b'x'*(1024*1024+1))))
    def test_json(self):
        with self.assertRaises(CollectionError):collect(self.cfg(),Opener(Response(b'bad')))
    def test_type(self):
        r=Response();r.headers={'Content-Type':'text/plain'}
        with self.assertRaises(CollectionError):collect(self.cfg(),Opener(r))
    def test_powerscale(self):
        r=collect(self.cfg(vendor='dell_powerscale'),Opener());self.assertEqual(r['endpoint'],'/platform/1/cluster/config')
if __name__=='__main__':unittest.main()
