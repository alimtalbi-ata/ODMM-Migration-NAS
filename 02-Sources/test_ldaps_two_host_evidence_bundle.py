import json
import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_runbook import signed_report, verify_report
from ldaps_two_host_evidence_bundle import SCENARIOS, scenario_evidence, consolidate, collect_files

KEY = b'z' * 32
INC = 'INC-1885'

class EvidenceBundleTests(unittest.TestCase):
    def record(self, scenario='baseline', outcome='PASS', incident_id=INC):
        return scenario_evidence(incident_id=incident_id, scenario=scenario, outcome=outcome,
                                 operator='operator-1', observations='manually observed', timestamp=10)
    def envelope(self, scenario='baseline', outcome='PASS', incident_id=INC):
        return signed_report(self.record(scenario, outcome, incident_id), key=KEY)
    def test_incomplete_is_review(self):
        result=consolidate([self.envelope()], key=KEY, incident_id=INC)
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertEqual(result['scenario_outcomes']['systemd_restart'], 'MISSING')
        self.assertFalse(result['cutover_authorized'])
    def test_complete_is_only_reported(self):
        result=consolidate([self.envelope(s) for s in SCENARIOS], key=KEY, incident_id=INC)
        self.assertEqual(result['status'], 'REPORTED_COMPLETE')
        self.assertFalse(result['remote_independence_proven'])
        self.assertTrue(result['manual_review_required'])
    def test_failed_is_review(self):
        self.assertEqual(consolidate([self.envelope('baseline','FAIL')],key=KEY,incident_id=INC)['status'],'REVIEW_REQUIRED')
    def test_not_executed_is_review(self):
        self.assertEqual(consolidate([self.envelope('baseline','NOT_EXECUTED')],key=KEY,incident_id=INC)['status'],'REVIEW_REQUIRED')
    def test_duplicate_refused(self):
        with self.assertRaises(IdentityPinError): consolidate([self.envelope(),self.envelope()],key=KEY,incident_id=INC)
    def test_mismatched_incident_refused(self):
        with self.assertRaises(IdentityPinError): consolidate([self.envelope(incident_id='other')],key=KEY,incident_id=INC)
    def test_bad_hmac_refused(self):
        env=self.envelope(); env['report']['outcome']='FAIL'
        with self.assertRaises(IdentityPinError): consolidate([env],key=KEY,incident_id=INC)
    def test_unsafe_refused_even_when_signed(self):
        record=self.record(); record['recovery_authorized']=True
        with self.assertRaises(IdentityPinError): consolidate([signed_report(record,key=KEY)],key=KEY,incident_id=INC)
    def test_unknown_scenario_refused(self):
        with self.assertRaises(IdentityPinError): self.record('unknown')
    def test_missing_operator_refused(self):
        with self.assertRaises(IdentityPinError): scenario_evidence(incident_id=INC,scenario='baseline',outcome='PASS',operator='',observations='x')
    def test_invalid_timestamp_refused(self):
        with self.assertRaises(IdentityPinError): scenario_evidence(incident_id=INC,scenario='baseline',outcome='PASS',operator='x',observations='x',timestamp=-1)
    def test_no_evidence_refused(self):
        with self.assertRaises(IdentityPinError): consolidate([],key=KEY,incident_id=INC)
    def test_file_collection_signed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'scenario.json'; dest=Path(tmp)/'bundle.json'
            src.write_text(json.dumps(self.envelope()))
            collect_files([src],key=KEY,incident_id=INC,output=dest)
            report=verify_report(json.loads(dest.read_text()),key=KEY)
            self.assertEqual(report['evidence_count'],1)
            self.assertEqual(dest.stat().st_mode & 0o777,0o600)
            with self.assertRaises(IdentityPinError): collect_files([src],key=KEY,incident_id=INC,output=dest)
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'scenario.json'; src.write_text(json.dumps(self.envelope()))
            link=Path(tmp)/'link.json'; link.symlink_to(src)
            with self.assertRaises(IdentityPinError): collect_files([link],key=KEY,incident_id=INC,output=Path(tmp)/'out')

if __name__ == '__main__': unittest.main()
