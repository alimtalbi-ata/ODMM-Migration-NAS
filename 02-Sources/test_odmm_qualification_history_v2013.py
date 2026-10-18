import copy
import unittest
from unittest.mock import patch
from odmm_qualification_history_v2013 import *
from odmm_qualification_campaign_v2012 import qualify

class Tests(unittest.TestCase):
    def setUp(self):
        self.p=profile("NetApp","Dell","NFS4","SMB3")
        self.c={"schema":"odmm.qualification.campaign.v2012", "fidelity":{"schema":"odmm.migration.fidelity.v2011"}}
    def test_profile(self): self.assertTrue(verify_profile(self.p))
    def test_profile_unknown_vendor(self):
        with self.assertRaises(ValueError): profile("Unknown","Dell","NFS4","SMB3")
    def test_profile_unknown_protocol(self):
        with self.assertRaises(ValueError): profile("NetApp","Dell","X","SMB3")
    def test_profile_tamper(self):
        p=copy.deepcopy(self.p);p['target']['vendor']='IBM';self.assertFalse(verify_profile(p))
    def test_profile_fail_closed(self):
        p=copy.deepcopy(self.p);p['cutover_authorized']=True;p['profile_sha256']=sha({k:v for k,v in p.items() if k!='profile_sha256'});self.assertFalse(verify_profile(p))
    def test_empty(self):
        with self.assertRaises(ValueError): build_history([],self.p)
    def test_invalid_campaign(self):
        with self.assertRaises(ValueError): build_history([{}],self.p)
    def test_chain_and_diff(self):
        from odmm_migration_fidelity_report_v2011 import build_report
        from odmm_qualification_campaign_v2012 import digest
        # Generate structurally valid campaigns without touching a NAS
        with patch('odmm_qualification_history_v2013.verify_campaign',return_value=True):
            c1={'report_sha256':'a'*64,'qualification':'BLOCKED','fidelity':{'report_sha256':'b'*64}}
            c2={'report_sha256':'c'*64,'qualification':'BLOCKED','fidelity':{'report_sha256':'d'*64}}
            h=build_history([c1,c2],self.p)
        self.assertTrue(verify_history(h))
        self.assertTrue(compare_history(h)['transitions'][0]['fidelity_report_changed'])
        self.assertFalse(compare_history(h)['cutover_authorized'])
    def test_chain_tamper(self):
        with patch('odmm_qualification_history_v2013.verify_campaign',return_value=True):
            h=build_history([{'report_sha256':'a','qualification':'BLOCKED','fidelity':{'report_sha256':'b'}}],self.p)
        h['entries'][0]['qualification']='QUALIFIED';self.assertFalse(verify_history(h))
    def test_chain_forged_cutover(self):
        with patch('odmm_qualification_history_v2013.verify_campaign',return_value=True):
            h=build_history([{'report_sha256':'a','qualification':'BLOCKED','fidelity':{'report_sha256':'b'}}],self.p)
        h['cutover_authorized']=True;h['history_sha256']=sha({k:v for k,v in h.items() if k!='history_sha256'})
        self.assertFalse(verify_history(h))
    def test_invalid_history(self):
        with self.assertRaises(ValueError):compare_history({})
    def test_required_evidence(self): self.assertIn('effective_access',self.p['required_evidence'])

if __name__=='__main__':unittest.main()
