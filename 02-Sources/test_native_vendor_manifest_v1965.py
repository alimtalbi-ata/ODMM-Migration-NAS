import unittest
import json
from native_vendor_manifest import seal_manifest, verify_manifest
from native_vendor_contracts import ContractRejected
from native_rotation_vendor_collector import make_readonly_collector

KEY=b'K'*32
CONTRACTS={'netapp_ontap': {'firmware':'9.15.1','asset_field':'id','state_field':'state'}}
class ManifestTests(unittest.TestCase):
    def setUp(self): self.m=seal_manifest(contracts=CONTRACTS,key=KEY,key_id='k1')
    def test_valid(self): self.assertEqual(verify_manifest(manifest=self.m,pinned_keys={'k1':KEY}),CONTRACTS)
    def test_tamper(self):
        m=json.loads(json.dumps(self.m));m['contracts']['netapp_ontap']['firmware']='9.16'
        with self.assertRaises(ContractRejected): verify_manifest(manifest=m,pinned_keys={'k1':KEY})
    def test_wrong_key(self):
        with self.assertRaises(ContractRejected): verify_manifest(manifest=self.m,pinned_keys={'k1':b'X'*32})
    def test_unknown_key(self):
        with self.assertRaises(ContractRejected): verify_manifest(manifest=self.m,pinned_keys={})
    def test_bad_schema(self):
        m=dict(self.m,schema=2)
        with self.assertRaises(ContractRejected): verify_manifest(manifest=m,pinned_keys={'k1':KEY})
    def test_short_key(self):
        with self.assertRaises(ContractRejected): seal_manifest(contracts=CONTRACTS,key=b'weak',key_id='k1')
    def test_production_requires_signed(self):
        with self.assertRaises(ValueError): self.make(production=True)
    def test_production_rejects_unsigned_override(self):
        with self.assertRaises(ValueError): self.make(production=True,approved_contracts=CONTRACTS,signed_manifest=self.m,pinned_manifest_keys={'k1':KEY})
    def make(self,**kwargs):
        return make_readonly_collector(vendor='netapp_ontap',transport=lambda url,h:(200,b'{"firmware":"9.15.1","id":"v1","state":"online"}'),trusted_origin='https://storage.example',auth_provider=lambda v:'token',state_mapper=lambda v,p:p['state'],**kwargs)
    def test_production_valid_observation(self):
        obs=self.make(production=True,signed_manifest=self.m,pinned_manifest_keys={'k1':KEY})
        self.assertEqual(obs('v1')['state'],'online')
    def test_production_rejects_bad_response(self):
        obs=self.make(production=True,signed_manifest=self.m,pinned_manifest_keys={'k1':KEY})
        with self.assertRaises(ContractRejected): obs('v2')
    def test_production_rejects_tampered_manifest(self):
        m=dict(self.m,mac='0'*64)
        with self.assertRaises(ContractRejected): self.make(production=True,signed_manifest=m,pinned_manifest_keys={'k1':KEY})
    def test_lab_backward_compatible(self): self.assertEqual(self.make()('v1')['state'],'online')
