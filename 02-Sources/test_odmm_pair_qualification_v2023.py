import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from odmm_pair_qualification_v2023 import campaign, verify

PROBES={'source':{'status':'UNSUPPORTED_PLATFORM','protocol':'UNKNOWN'},
        'target':{'status':'UNSUPPORTED_PLATFORM','protocol':'UNKNOWN'}}

class TestPairQualification(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a=Path(self.tmp.name)/'a';self.b=Path(self.tmp.name)/'b'
        self.a.mkdir();self.b.mkdir()
        (self.a/'data.txt').write_text('hello')
        (self.b/'data.txt').write_text('hello')
    def run_campaign(self, **kw):
        return campaign(self.a,self.b,windows_probes=PROBES,**({'required':['xattrs']} | kw))
    def test_matching_still_blocked(self):
        r=self.run_campaign()
        self.assertTrue(verify(r));self.assertFalse(r['cutover_authorized'])
    def test_metadata_difference(self):
        (self.b/'data.txt').write_text('different')
        r=self.run_campaign()
        self.assertEqual(r['status'],'MISMATCH')
        self.assertTrue(any(x['risk']=='EXTENDED_METADATA_MISMATCH' for x in r['risks']))
    def test_tamper(self):
        r=self.run_campaign();r['risk_count']=0
        self.assertFalse(verify(r))
    def test_symlink_root(self):
        link=Path(self.tmp.name)/'link';link.symlink_to(self.a, target_is_directory=True)
        with self.assertRaises(ValueError):
            campaign(link,self.b,required=['xattrs'],windows_probes=PROBES)
    def test_overlap(self):
        with self.assertRaises(ValueError):
            campaign(self.a,self.a,required=['xattrs'],windows_probes=PROBES)
    def test_no_external_engine(self):
        with self.assertRaisesRegex(ValueError,'EXTERNAL_ENGINE'):
            self.run_campaign(strategy='RSYNC')
    def test_entry_limit(self):
        with self.assertRaises(ValueError):self.run_campaign(max_entries=0)
    def test_byte_limit(self):
        with self.assertRaises(Exception):self.run_campaign(max_bytes=1)
    def test_invalid_domains(self):
        with self.assertRaises(ValueError):self.run_campaign(required=['nonexistent'])
    def test_no_nas_write(self):
        r=self.run_campaign()
        self.assertFalse(r['writes_to_nas'])
        self.assertEqual((self.a/'data.txt').read_text(),'hello')
if __name__=='__main__':unittest.main()
