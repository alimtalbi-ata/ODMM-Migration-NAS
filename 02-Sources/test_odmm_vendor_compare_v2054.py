import unittest
from odmm_vendor_compare_v2054 import compare_exports
class TestComparison(unittest.TestCase):
    def setUp(self):
        self.a={"version":"9.16.1","svms":[{},{}]}
        self.b={"version":"9.9","zones":[{}]}
    def test_vendor_cross_compare(self):
        r=compare_exports("netapp_ontap",self.a,"dell_powerscale",self.b)
        self.assertFalse(r["cutover_authorized"])
        self.assertEqual(r["source"]["reported_object_count"],2)
    def test_digest_stable(self):
        x=compare_exports("netapp_ontap",self.a,"dell_powerscale",self.b)
        y=compare_exports("netapp_ontap",self.a,"dell_powerscale",self.b)
        self.assertEqual(x["evidence_sha256"],y["evidence_sha256"])
    def test_changed_data_changes_digest(self):
        x=compare_exports("netapp_ontap",self.a,"dell_powerscale",self.b)
        self.a["svms"].append({})
        y=compare_exports("netapp_ontap",self.a,"dell_powerscale",self.b)
        self.assertNotEqual(x["evidence_sha256"],y["evidence_sha256"])
    def test_missing_version_fails_closed(self):
        with self.assertRaises(ValueError):compare_exports("netapp_ontap",{},"dell_powerscale",self.b)
    def test_unknown_vendor_fails_closed(self):
        with self.assertRaises(ValueError):compare_exports("bogus",self.a,"dell_powerscale",self.b)
    def test_no_claim_of_acl(self):
        r=compare_exports("netapp_ontap",self.a,"dell_powerscale",self.b)
        self.assertEqual(r["acl_fidelity"],"UNVERIFIED")
