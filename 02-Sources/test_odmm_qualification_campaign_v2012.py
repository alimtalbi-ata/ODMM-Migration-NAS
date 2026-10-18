import copy
import tempfile
import unittest
from pathlib import Path
from odmm_qualification_campaign_v2012 import qualify,verify_campaign,save_report,CampaignError

class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.a=self.base/'source';self.b=self.base/'target'
        self.a.mkdir();self.b.mkdir()
        (self.a/'file.txt').write_text('abc');(self.b/'file.txt').write_text('abc')
        import shutil
        shutil.copystat(self.a/'file.txt',self.b/'file.txt')
    def test_campaign_digest(self):
        r=qualify(self.a,self.b);self.assertTrue(verify_campaign(r));self.assertFalse(r['cutover_authorized'])
    def test_detect_content_difference(self):
        (self.b/'file.txt').write_text('different');r=qualify(self.a,self.b)
        self.assertEqual(r['fidelity']['domains']['content']['status'],'BLOCKED')
    def test_missing_file(self):
        (self.b/'file.txt').unlink();r=qualify(self.a,self.b)
        self.assertEqual(r['fidelity']['domains']['content']['status'],'BLOCKED')
    def test_tampering(self):
        r=qualify(self.a,self.b);r['fidelity']['status']='PASS';self.assertFalse(verify_campaign(r))
    def test_same_root_rejected(self):
        with self.assertRaises(CampaignError):qualify(self.a,self.a)
    def test_nested_roots_rejected(self):
        nested=self.a/'nested';nested.mkdir()
        with self.assertRaises(CampaignError):qualify(self.a,nested)
    def test_symlink_root_rejected(self):
        link=self.base/'link';link.symlink_to(self.a,target_is_directory=True)
        with self.assertRaises(CampaignError):qualify(link,self.b)
    def test_report_outside_roots(self):
        r=qualify(self.a,self.b);p=save_report(r,self.base/'report.json',self.a,self.b)
        self.assertTrue(p.is_file())
    def test_report_inside_root_blocked(self):
        r=qualify(self.a,self.b)
        with self.assertRaises(CampaignError):save_report(r,self.a/'report.json',self.a,self.b)
    def test_existing_report_not_overwritten(self):
        p=self.base/'report.json';p.write_text('sentinel')
        with self.assertRaises(FileExistsError):save_report(qualify(self.a,self.b),p,self.a,self.b)
        self.assertEqual(p.read_text(),'sentinel')
    def test_entry_limit(self):
        from odmm_nas_evidence_collector_v2006 import CollectionError
        with self.assertRaises(CollectionError):qualify(self.a,self.b,max_entries=0)
if __name__=='__main__':unittest.main()
