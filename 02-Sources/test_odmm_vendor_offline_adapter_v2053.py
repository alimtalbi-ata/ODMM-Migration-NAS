import unittest
from odmm_vendor_offline_adapter_v2053 import normalize_export
class TestVendorAdapter(unittest.TestCase):
    def test_ontap(self):
        r=normalize_export("netapp_ontap", {"version":"9.16.1","svms":[{}]})
        self.assertEqual(r["reported_object_count"],1)
        self.assertFalse(r["cutover_authorized"])
    def test_powerscale(self):
        r=normalize_export("dell_powerscale", {"version":"9.9","zones":[]})
        self.assertEqual(r["status"],"UNVERIFIED")
    def test_unknown(self):
        with self.assertRaises(ValueError): normalize_export("other",{})
    def test_missing(self):
        with self.assertRaises(ValueError): normalize_export("netapp_ontap",{"version":"9"})
    def test_bad_list(self):
        with self.assertRaises(ValueError): normalize_export("dell_powerscale",{"version":"9","zones":"bad"})
    def test_bad_version(self):
        with self.assertRaises(ValueError): normalize_export("netapp_ontap",{"version":None,"svms":[]})
if __name__=="__main__": unittest.main()
