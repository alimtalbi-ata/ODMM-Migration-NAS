import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_runbook import run_probe, signed_report, verify_report, write_report

KEY = b'k' * 32
HEAD = 'a' * 64

class FakeQualifier:
    def __init__(self, result=None): self.result=result
    def probe(self, **kwargs):
        if not kwargs['operator_confirmed']: raise IdentityPinError('CONFIRMATION_REQUIRED')
        return self.result or {'status':'TWO_HOST_REMOTE_PROBE_VERIFIED', 'count':1,
                               'remote_independence_proven':False, 'cutover_authorized':False}

class TwoHostRunbookTests(unittest.TestCase):
    def report(self):
        return run_probe(FakeQualifier(), expected_count=1, expected_last_mac=HEAD,
                         incident_id='INC-001', operator_confirmed=True)
    def test_success_is_not_cutover(self):
        report=self.report()
        self.assertFalse(report['cutover_authorized'])
        self.assertEqual(report['tests']['systemd_restart'],'NOT_EXECUTED')
        self.assertEqual(report['tests']['network_partition'],'NOT_EXECUTED')
    def test_operator_required(self):
        with self.assertRaises(IdentityPinError):
            run_probe(FakeQualifier(),expected_count=1,expected_last_mac=HEAD,incident_id='i',operator_confirmed=False)
    def test_reject_unverified(self):
        with self.assertRaises(IdentityPinError):
            run_probe(FakeQualifier({'status':'INVALID'}),expected_count=1,expected_last_mac=HEAD,incident_id='i',operator_confirmed=True)
    def test_signature_roundtrip(self):
        r=self.report(); self.assertEqual(verify_report(signed_report(r,key=KEY),key=KEY),r)
    def test_tamper_detected(self):
        e=signed_report(self.report(),key=KEY); e['report']['cutover_authorized']=True
        with self.assertRaises(IdentityPinError): verify_report(e,key=KEY)
    def test_wrong_key(self):
        with self.assertRaises(IdentityPinError): verify_report(signed_report(self.report(),key=KEY),key=b'x'*32)
    def test_short_key(self):
        with self.assertRaises(IdentityPinError): signed_report(self.report(),key=b'123')
    def test_unsafe_report(self):
        r=self.report(); r['cutover_authorized']=True
        with self.assertRaises(IdentityPinError): signed_report(r,key=KEY)
    def test_atomic_write_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.json'; envelope=signed_report(self.report(),key=KEY)
            write_report(path,envelope)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            import json
            self.assertEqual(verify_report(json.loads(path.read_text()),key=KEY),self.report())
    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.json'; envelope=signed_report(self.report(),key=KEY)
            write_report(path,envelope)
            with self.assertRaises(IdentityPinError): write_report(path,envelope)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'target'; target.write_text('keep')
            link=Path(tmp)/'link'; link.symlink_to(target)
            with self.assertRaises(IdentityPinError): write_report(link,signed_report(self.report(),key=KEY))
            self.assertEqual(target.read_text(),'keep')
    def test_reject_invalid_envelope(self):
        with self.assertRaises(IdentityPinError): verify_report({'report':self.report()},key=KEY)

if __name__=='__main__': unittest.main()
