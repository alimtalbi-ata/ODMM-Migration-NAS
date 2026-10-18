import unittest
from native_vendor_contracts import validate_vendor_observation, ContractRejected
from native_rotation_vendor_collector import make_readonly_collector

C={'netapp_ontap':{'firmware':'9.15.1','asset_field':'id','state_field':'state'}}
P={'firmware':'9.15.1','id':'vol1','state':'online'}

class ContractTests(unittest.TestCase):
    def check(self, p=None, c=None, asset='vol1', vendor='netapp_ontap'):
        return validate_vendor_observation(vendor=vendor,payload=P if p is None else p,asset_id=asset,approved_contracts=C if c is None else c)
    def test_valid(self): self.assertEqual(self.check(),'online')
    def test_firmware(self):
        with self.assertRaises(ContractRejected): self.check({**P,'firmware':'9.16'})
    def test_asset(self):
        with self.assertRaises(ContractRejected): self.check(asset='vol2')
    def test_extra_fields(self):
        with self.assertRaises(ContractRejected): self.check({**P,'debug':'secret'})
    def test_missing_fields(self):
        with self.assertRaises(ContractRejected): self.check({'firmware':'9.15.1','id':'vol1'})
    def test_state(self):
        with self.assertRaises(ContractRejected): self.check({**P,'state':'DELETE'})
    def test_state_type(self):
        with self.assertRaises(ContractRejected): self.check({**P,'state':True})
    def test_vendor(self):
        with self.assertRaises(ContractRejected): self.check(vendor='pure_flasharray')
    def test_empty_registry(self):
        with self.assertRaises(ContractRejected): self.check(c={})
    def test_invalid_contract(self):
        with self.assertRaises(ContractRejected): self.check(c={'netapp_ontap':{'firmware':'9.15.1'}})
    def test_collector_integration(self):
        import json
        observe=make_readonly_collector(vendor='netapp_ontap',transport=lambda u,h:(200,json.dumps(P).encode()),trusted_origin='https://storage.example',auth_provider=lambda v:'token',state_mapper=lambda v,p:'invalid',approved_contracts=C)
        self.assertEqual(observe('vol1')['state'],'online')
    def test_collector_rejects_wrong_firmware(self):
        import json
        observe=make_readonly_collector(vendor='netapp_ontap',transport=lambda u,h:(200,json.dumps({**P,'firmware':'9.16'}).encode()),trusted_origin='https://storage.example',auth_provider=lambda v:'token',state_mapper=lambda v,p:'online',approved_contracts=C)
        with self.assertRaises(ContractRejected): observe('vol1')
