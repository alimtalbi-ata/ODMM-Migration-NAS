import unittest,hashlib
from effective_access_compare import canonical
from access_probe_bridge import observation_from_probe,compare_probe_pairs,ProbeBridgeError

def bundle(outcome='OPEN_READ_SUCCEEDED'):
    report={'schema':'odmm.readonly-access-probe.v1','action':'open_readonly','outcome':outcome,
    'execution_euid':1000,'execution_egid':1000,'identity_impersonation':False,
    'file_content_read':False,'write_performed':False,'remote_nas_identity_verified':False,
    'effective_acl_equivalence_verified':False,'production_qualified':False}
    return {'report':report,'sha256':hashlib.sha256(canonical(report)).hexdigest()}

class BridgeTests(unittest.TestCase):
    def test_allow(self): self.assertEqual(observation_from_probe(bundle(),'p','o')['observation']['decision'],'ALLOW')
    def test_deny(self): self.assertEqual(observation_from_probe(bundle('OPEN_READ_DENIED'),'p','o')['observation']['decision'],'DENY')
    def test_tamper(self):
        b=bundle();b['report']['outcome']='OPEN_READ_DENIED'
        with self.assertRaises(ProbeBridgeError): observation_from_probe(b,'p','o')
    def test_unsafe_flags(self):
        b=bundle();b['report']['production_qualified']=True;b['sha256']=hashlib.sha256(canonical(b['report'])).hexdigest()
        with self.assertRaises(ProbeBridgeError): observation_from_probe(b,'p','o')
    def test_invalid_alias(self):
        with self.assertRaises(ProbeBridgeError): observation_from_probe(bundle(),'../p','o')
    def test_unknown_outcome(self):
        b=bundle('UNKNOWN')
        with self.assertRaises(ProbeBridgeError): observation_from_probe(b,'p','o')
    def test_match(self):
        x={'bundle':bundle(),'principal_alias':'p','object_alias':'o'}
        result=compare_probe_pairs('NFSv4',[x],[x]);self.assertEqual(result['comparison']['report']['summary']['MATCH'],1)
        self.assertFalse(result['production_qualified'])
    def test_mismatch(self):
        x={'bundle':bundle(),'principal_alias':'p','object_alias':'o'}
        y={'bundle':bundle('OPEN_READ_DENIED'),'principal_alias':'p','object_alias':'o'}
        self.assertEqual(compare_probe_pairs('SMB',[x],[y])['comparison']['report']['summary']['MISMATCH'],1)
    def test_missing(self):
        x={'bundle':bundle(),'principal_alias':'p','object_alias':'o'}
        y={'bundle':bundle(),'principal_alias':'p','object_alias':'other'}
        self.assertEqual(compare_probe_pairs('SMB',[x],[y])['comparison']['report']['summary']['INDETERMINATE'],2)
    def test_empty(self):
        with self.assertRaises(ProbeBridgeError): compare_probe_pairs('SMB',[],[])
    def test_reproducible(self):
        x={'bundle':bundle(),'principal_alias':'p','object_alias':'o'}
        self.assertEqual(compare_probe_pairs('SMB',[x],[x]),compare_probe_pairs('SMB',[x],[x]))
