import unittest
from odmm_storage_catalog_v2002 import solutions,assess_pair,export_catalog,REQUIRED_FIDELITY

class CatalogTests(unittest.TestCase):
    def test_broad_coverage(self):
        c=export_catalog(); self.assertGreaterEqual(len(c['solutions']),35)
        self.assertGreaterEqual(len({s['vendor'] for s in c['solutions']}),25)
    def test_filters(self):
        self.assertTrue(all('S3' in x.protocols for x in solutions(protocol='S3')))
        self.assertTrue(solutions(vendor='NetApp'))
        with self.assertRaises(ValueError): solutions(protocol='FTP')
    def test_pair_never_certified(self):
        src=solutions(vendor='NetApp')[0]; dst=solutions(vendor='Dell')[0]
        a=assess_pair(src,dst,evidence={k:True for k in REQUIRED_FIDELITY})
        self.assertFalse(a['cutover_authorized']); self.assertFalse(a['acl_fidelity_verified'])
        self.assertEqual(a['status'],'DISCOVERY_ONLY')
    def test_missing_acl_blocks(self):
        a=assess_pair(solutions(vendor='NetApp')[0],solutions(vendor='QNAP')[0],evidence={'content':True})
        self.assertIn('acl',a['missing_evidence'])
    def test_unknown_and_invalid(self):
        with self.assertRaises(ValueError): assess_pair('invented',solutions()[0])
        with self.assertRaises(ValueError): assess_pair(solutions()[0],solutions()[1],evidence=[])
    def test_catalog_metadata(self):
        c=export_catalog(); self.assertFalse(c['production_qualified']); self.assertIn('smb_security_descriptor',c['fidelity_dimensions'])
if __name__=='__main__': unittest.main()
