import unittest
from odmm_nas_firmware_evidence_v2130 import inspect_endpoint,inspect_pair

def ep(v='netapp',**overrides):
    e=dict(vendor=v,model='NAS-TEST',firmware='1.0',serial_ref='opaque-ref',
      protocols=['NFS4','SMB3'],acl_models=['NFS4','NTFS'],evidence_id='ev-1',
      collected_at='2026-10-15T12:00:00+00:00',collection_method='API_READONLY',
      pagination_complete=True,inventory_complete=True,read_only=True,
      vendor_api_qualified=True,acl_evidence_complete=True)
    e.update(overrides);return e

class TestFirmwareEvidence(unittest.TestCase):
    def test_pair_conditional_never_certified(self):
        r=inspect_pair(ep(),ep('pure'));self.assertEqual(r.classification,'CONDITIONAL');self.assertFalse(r.certified);self.assertFalse(r.cutover_authorized)
    def test_onefs_reverse(self):
        self.assertEqual(inspect_pair(ep('onefs'),ep('netapp')).classification,'CONDITIONAL')
    def test_missing_firmware(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(firmware=''))
    def test_unrecognized_vendor(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep('imaginary'))
    def test_mismatch_vendor(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(),expected_vendor='pure')
    def test_bad_protocol(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(protocols=['FTP']))
    def test_duplicate_acl(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(acl_models=['NTFS','NTFS']))
    def test_no_common_protocol(self):
        r=inspect_pair(ep(protocols=['NFS4']),ep('pure',protocols=['SMB3']))
        self.assertEqual(r.classification,'NOT_QUALIFIED');self.assertIn('NO_COMMON_PROTOCOL',r.blockers)
    def test_no_common_acl(self):
        r=inspect_pair(ep(acl_models=['NFS4']),ep('pure',acl_models=['NTFS']))
        self.assertIn('NO_COMMON_ACL_MODEL',r.blockers)
    def test_incomplete_pagination(self):
        r=inspect_pair(ep(pagination_complete=False),ep('pure'))
        self.assertEqual(r.classification,'NOT_QUALIFIED')
    def test_manual_collection(self):
        self.assertIn('NOT_LIVE_APPLIANCE_DISCOVERY',inspect_endpoint(ep(collection_method='MANUAL')).warnings)
    def test_unqualified_api(self):
        self.assertEqual(inspect_pair(ep(vendor_api_qualified=False),ep('pure')).classification,'NOT_QUALIFIED')
    def test_naive_timestamp(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(collected_at='2026-10-15T12:00:00'))
    def test_invalid_method(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(collection_method='HTTP_WRITE'))
    def test_control_chars(self):
        with self.assertRaises(ValueError):inspect_endpoint(ep(model='A\nB'))
    def test_same_vendor_blocker(self):
        self.assertIn('SAME_VENDOR_REQUIRES_QUALIFICATION',inspect_pair(ep(),ep()).blockers)
    def test_no_invented_certification(self):
        r=inspect_pair(ep(),ep('pure'));self.assertIn('NO_INDEPENDENT_HARDWARE_FIRMWARE_CERTIFICATION',r.blockers)
