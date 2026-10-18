import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_qualification import TwoHostQualification,validate_target

HEAD='a'*64

def resolver(address):
    return lambda host,port,**kw: [(2,1,6,'',(address,port))]

class FakeVerifier:
    calls=0
    def __init__(self,**kwargs): self.kwargs=kwargs
    def verify(self,**kwargs):
        FakeVerifier.calls+=1
        return {'status':'REMOTE_WITNESS_VERIFIED','count':kwargs['expected_count']}

class TwoHostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for name in ('ca','cert','key'):
            (Path(self.temp.name)/name).write_text('test')
        self.args=dict(host='witness.example',port=9443,cafile=str(Path(self.temp.name)/'ca'),
            certfile=str(Path(self.temp.name)/'cert'),keyfile=str(Path(self.temp.name)/'key'),
            witness_key=b'x'*32,resolver=resolver('192.0.2.10'),verifier_factory=FakeVerifier,
            clock=lambda:12345)
        FakeVerifier.calls=0
    def harness(self): return TwoHostQualification(**self.args)
    def test_preflight_no_network_probe(self):
        self.assertFalse(self.harness().preflight()['network_tested'])
        self.assertEqual(FakeVerifier.calls,0)
    def test_probe_explicit_confirmation(self):
        with self.assertRaisesRegex(IdentityPinError,'CONFIRMATION'):
            self.harness().probe(expected_count=1,expected_last_mac=HEAD,incident_id='I')
    def test_probe_non_authorizing(self):
        r=self.harness().probe(expected_count=1,expected_last_mac=HEAD,incident_id='I',operator_confirmed=True)
        self.assertEqual(r['status'],'TWO_HOST_REMOTE_PROBE_VERIFIED')
        self.assertFalse(r['cutover_authorized'])
        self.assertFalse(r['remote_independence_proven'])
        self.assertEqual(FakeVerifier.calls,1)
    def test_loopback_refused(self):
        self.args['resolver']=resolver('127.0.0.1')
        with self.assertRaisesRegex(IdentityPinError,'NOT_INDEPENDENT'):
            self.harness().preflight()
    def test_unspecified_refused(self):
        self.args['resolver']=resolver('0.0.0.0')
        with self.assertRaisesRegex(IdentityPinError,'NOT_INDEPENDENT'):
            self.harness().preflight()
    def test_linklocal_refused(self):
        self.args['resolver']=resolver('169.254.1.2')
        with self.assertRaisesRegex(IdentityPinError,'NOT_INDEPENDENT'):
            self.harness().preflight()
    def test_multicast_refused(self):
        self.args['resolver']=resolver('224.0.0.1')
        with self.assertRaisesRegex(IdentityPinError,'NOT_INDEPENDENT'):
            self.harness().preflight()
    def test_missing_certificate_refused(self):
        (Path(self.temp.name)/'cert').unlink()
        with self.assertRaisesRegex(IdentityPinError,'CREDENTIAL_MISSING'):
            self.harness().preflight()
    def test_symlink_certificate_refused(self):
        p=Path(self.temp.name)/'cert';p.unlink();p.symlink_to(Path(self.temp.name)/'ca')
        with self.assertRaisesRegex(IdentityPinError,'CREDENTIAL_MISSING'):
            self.harness().preflight()
    def test_dns_failure_refused(self):
        self.args['resolver']=lambda *a,**k: (_ for _ in ()).throw(OSError('offline'))
        with self.assertRaisesRegex(IdentityPinError,'DNS_UNAVAILABLE'):
            self.harness().preflight()
    def test_empty_dns_refused(self):
        self.args['resolver']=lambda *a,**k: []
        with self.assertRaisesRegex(IdentityPinError,'DNS_EMPTY'):
            self.harness().preflight()
    def test_bad_port_refused(self):
        self.args['port']=0
        with self.assertRaisesRegex(IdentityPinError,'PORT_INVALID'):
            self.harness().preflight()
    def test_bad_incident_refused(self):
        with self.assertRaisesRegex(IdentityPinError,'INCIDENT_INVALID'):
            self.harness().probe(expected_count=0,expected_last_mac=HEAD,incident_id='bad\nname',operator_confirmed=True)
    def test_divergence_propagates(self):
        class Divergent(FakeVerifier):
            def verify(self,**kwargs): raise IdentityPinError('REMOTE_WITNESS_DIVERGENCE_MANUAL_REVIEW')
        self.args['verifier_factory']=Divergent
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):
            self.harness().probe(expected_count=0,expected_last_mac=HEAD,incident_id='I',operator_confirmed=True)
    def test_ipv6_loopback_refused(self):
        self.args['resolver']=resolver('::1')
        with self.assertRaisesRegex(IdentityPinError,'NOT_INDEPENDENT'):
            self.harness().preflight()

if __name__=='__main__': unittest.main()
