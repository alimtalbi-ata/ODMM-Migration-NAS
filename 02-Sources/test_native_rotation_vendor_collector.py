import unittest
from native_rotation_vendor_collector import make_readonly_collector

class VendorCollectorTests(unittest.TestCase):
    def factory(self, **kw):
        return make_readonly_collector(vendor=kw.get('vendor','netapp_ontap'),
          transport=kw.get('transport',lambda url,headers:(200,b'{"status":"ready"}')),
          trusted_origin=kw.get('origin','https://storage.example'),
          auth_provider=kw.get('auth',lambda v:'secret'),
          state_mapper=kw.get('mapper',lambda v,p:p['status']))
    def test_happy(self):
        self.assertEqual(self.factory()('vol-1')['state'],'ready')
    def test_unknown_vendor(self):
        with self.assertRaises(ValueError): self.factory(vendor='unknown')
    def test_http_forbidden(self):
        with self.assertRaises(ValueError): self.factory(origin='http://storage.example')
    def test_credentials_in_origin(self):
        with self.assertRaises(ValueError): self.factory(origin='https://a@storage.example')
    def test_asset_injection(self):
        with self.assertRaises(ValueError): self.factory()('../delete')
    def test_failed_response(self):
        with self.assertRaises(ValueError): self.factory(transport=lambda u,h:(401,b'{}'))('vol1')
    def test_oversized(self):
        with self.assertRaises(ValueError): self.factory(transport=lambda u,h:(200,b'a'*65537))('vol1')
    def test_bad_json(self):
        with self.assertRaises(ValueError): self.factory(transport=lambda u,h:(200,b'{'))('vol1')
    def test_bad_state(self):
        with self.assertRaises(ValueError): self.factory(mapper=lambda v,p:None)('vol1')
    def test_no_retry(self):
        calls=[]
        def fail(u,h):
            calls.append(1); raise TimeoutError()
        with self.assertRaises(TimeoutError): self.factory(transport=fail)('vol1')
        self.assertEqual(len(calls),1)
    def test_pure(self):
        self.assertEqual(self.factory(vendor='pure_flasharray')('vol1')['state'],'ready')
    def test_dell(self):
        self.assertEqual(self.factory(vendor='dell_powerscale')('vol1')['state'],'ready')

if __name__=='__main__': unittest.main()
