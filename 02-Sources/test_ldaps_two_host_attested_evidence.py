import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_runbook import signed_report
from ldaps_two_host_attested_evidence import attestation, verify_pair, ReplayRegistry
KEYS = {'source': b's'*32, 'witness': b'w'*32}
RUN='run-1886-unique-123'
class AttestedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.registry=ReplayRegistry(Path(self.tmp.name)/'seen.sqlite')
    def pair(self):
        return [signed_report(attestation(host=h,run_id=RUN,incident_id='inc',scenario='restart',
            observation='probe returned status',timestamp=100,nonce=h*32),key=KEYS[h]) for h in KEYS]
    def verify(self,pair=None,**kw):
        return verify_pair(self.pair() if pair is None else pair,keys=KEYS,run_id=RUN,
            incident_id='inc',scenario='restart',now=100,**kw)
    def test_valid_pair_review_only(self):
        r=self.verify(); self.assertFalse(r['remote_independence_proven']); self.assertFalse(r['cutover_authorized'])
    def test_register_and_replay(self):
        r=self.verify(); self.registry.register(r)
        with self.assertRaises(IdentityPinError): self.registry.register(r)
    def test_replay_after_reopen(self):
        r=self.verify(); self.registry.register(r)
        with self.assertRaises(IdentityPinError): ReplayRegistry(self.registry.path).register(r)
    def test_duplicate_host(self):
        p=self.pair(); p[1]=p[0]
        with self.assertRaises(IdentityPinError): self.verify(p)
    def test_wrong_key(self):
        p=self.pair(); p[0]=signed_report(p[0]['report'],key=KEYS['witness'])
        with self.assertRaises(IdentityPinError): self.verify(p)
    def test_wrong_run(self):
        p=self.pair(); p[0]['report']['run_id']='other'
        with self.assertRaises(IdentityPinError): self.verify(p)
    def test_future(self):
        with self.assertRaises(IdentityPinError): verify_pair(self.pair(),keys=KEYS,run_id=RUN,incident_id='inc',scenario='restart',now=99)
    def test_expired(self):
        with self.assertRaises(IdentityPinError): verify_pair(self.pair(),keys=KEYS,run_id=RUN,incident_id='inc',scenario='restart',now=5000)
    def test_shared_key_refused(self):
        with self.assertRaises(IdentityPinError): verify_pair(self.pair(),keys={'source':KEYS['source'],'witness':KEYS['source']},run_id=RUN,incident_id='inc',scenario='restart')
    def test_unsafe_claim(self):
        p=self.pair(); p[0]['report']['cutover_authorized']=True
        with self.assertRaises(IdentityPinError): self.verify(p)
    def test_repeated_nonce(self):
        p=self.pair(); p[1]['report']['nonce']=p[0]['report']['nonce']; p[1]=signed_report(p[1]['report'],key=KEYS['witness'])
        with self.assertRaises(IdentityPinError): self.verify(p)
    def test_invalid_registry_report(self):
        with self.assertRaises(IdentityPinError): self.registry.register({'status':'OK','host_evidence':[]})
    def test_second_run_same_host_rejected(self):
        r=self.verify(); self.registry.register(r)
        r['host_evidence'][0]['nonce']='different-nonce-value-000000000000'
        with self.assertRaises(IdentityPinError): self.registry.register(r)
    def test_invalid_nonce(self):
        with self.assertRaises(IdentityPinError): attestation(host='source',run_id=RUN,incident_id='inc',scenario='x',observation='x',timestamp=1,nonce='short')
if __name__=='__main__': unittest.main()
