"""ODMM V201.5 isolated tests. Author: Abdelhalim Talbi."""
import copy
import tempfile
import unittest
from pathlib import Path
from odmm_fidelity_fixtures_v2014 import create_fixtures
from odmm_fixture_campaign_v2015 import bind_fixture_campaign,verify_binding

class FixtureCampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.src=root/'src';self.dst=root/'dst'
        self.manifest=create_fixtures(self.src,max_bytes=4096)
        self.dst.mkdir()
        import shutil
        shutil.copytree(self.src,self.dst,dirs_exist_ok=True,symlinks=True)
    def test_binding_valid(self):
        r=bind_fixture_campaign(self.src,self.dst,self.manifest)
        self.assertTrue(verify_binding(r))
    def test_no_cutover(self):
        self.assertFalse(bind_fixture_campaign(self.src,self.dst,self.manifest)['cutover_authorized'])
    def test_acl_unverified(self):
        self.assertEqual(bind_fixture_campaign(self.src,self.dst,self.manifest)['domain_status']['acl'],'UNVERIFIED')
    def test_access_unverified(self):
        self.assertEqual(bind_fixture_campaign(self.src,self.dst,self.manifest)['domain_status']['effective_access'],'UNVERIFIED')
    def test_tamper_report(self):
        r=bind_fixture_campaign(self.src,self.dst,self.manifest);r['status']='PASS';self.assertFalse(verify_binding(r))
    def test_tamper_nested_campaign(self):
        r=bind_fixture_campaign(self.src,self.dst,self.manifest);r['campaign']['qualification']='PASS';self.assertFalse(verify_binding(r))
    def test_modified_source_rejected(self):
        (self.src/'binary.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'SOURCE_FIXTURE_MISMATCH'):
            bind_fixture_campaign(self.src,self.dst,self.manifest)
    def test_missing_target_detected(self):
        (self.dst/'binary.bin').unlink()
        r=bind_fixture_campaign(self.src,self.dst,self.manifest)
        self.assertEqual(r['domain_status']['content'],'BLOCKED')
    def test_changed_target_detected(self):
        (self.dst/'binary.bin').write_bytes(b'changed')
        r=bind_fixture_campaign(self.src,self.dst,self.manifest)
        self.assertEqual(r['domain_status']['content'],'BLOCKED')
    def test_manifest_tamper_rejected(self):
        m=copy.deepcopy(self.manifest);m['entries'][0]['path']='evil'
        with self.assertRaises(ValueError):bind_fixture_campaign(self.src,self.dst,m)
    def test_entry_budget(self):
        with self.assertRaises((ValueError,RuntimeError)):
            bind_fixture_campaign(self.src,self.dst,self.manifest,max_entries=1)
if __name__=='__main__':unittest.main()
