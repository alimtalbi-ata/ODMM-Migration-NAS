import copy
import unittest
from odmm_migration_fidelity_report_v2011 import build_report, verify_report_digest, FidelityReportError

def inventory(content='abc', mode=420):
    return {'schema':'odmm.nas.readonly.inventory.v2006','entry_count':1,'entries':{'file':{
        'kind':'file','size':3,'sha256':content,'owner':100,'group':100,'mode':mode,'mtime_ns':1,'xattrs':{}}}}

class Tests(unittest.TestCase):
    def test_equal_still_blocks(self):
        r=build_report(inventory(),inventory());self.assertFalse(r['cutover_authorized']);self.assertEqual(r['domains']['content']['status'],'OBSERVED_MATCH_NOT_ATTESTED')
    def test_content_difference(self):
        r=build_report(inventory(),inventory('xyz'));self.assertEqual(r['domains']['content']['status'],'BLOCKED')
    def test_metadata_difference(self):
        r=build_report(inventory(),inventory(mode=384));self.assertEqual(r['domains']['metadata']['status'],'BLOCKED')
    def test_missing_target(self):
        t=inventory();t['entries']={};t['entry_count']=0
        self.assertEqual(build_report(inventory(),t)['domains']['content']['status'],'BLOCKED')
    def test_empty_pair(self):
        a=inventory();a['entries']={};a['entry_count']=0
        self.assertEqual(build_report(a,a)['domains']['content']['status'],'BLOCKED')
    def test_missing_acl_access(self):
        r=build_report(inventory(),inventory());self.assertEqual(r['domains']['acl']['status'],'UNVERIFIED');self.assertEqual(r['domains']['effective_access']['status'],'UNVERIFIED')
    def test_unrecognized_reports(self):
        r=build_report(inventory(),inventory(),acl_report={'schema':'other'},access_report={'schema':'other'});self.assertEqual(r['domains']['acl']['status'],'BLOCKED')
    def test_recognized_access_not_attested(self):
        r=build_report(inventory(),inventory(),access_report={'schema':'odmm.access.evidence.v2010'});self.assertEqual(r['domains']['effective_access']['status'],'UNVERIFIED')
    def test_digest_tamper(self):
        r=build_report(inventory(),inventory());self.assertTrue(verify_report_digest(r));r['source_entries']=4;self.assertFalse(verify_report_digest(r))
    def test_bad_counts(self):
        a=inventory();a['entry_count']=2
        with self.assertRaises(FidelityReportError):build_report(a,inventory())
    def test_no_domain_optout(self):
        with self.assertRaises(FidelityReportError):build_report(inventory(),inventory(),required_domains=('content',))

if __name__=='__main__': unittest.main()
