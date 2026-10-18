import unittest
from unittest.mock import patch
from capability_probe import qualification_matrix

class CapabilityProbeTests(unittest.TestCase):
    def test_invalid_protocol_blocked(self):
        self.assertEqual(qualification_matrix([{'protocol':'NFSv3','mountpoint':'/mnt/x'}])['report']['rows'][0]['status'],'BLOCKED')
    def test_invalid_path_blocked(self):
        self.assertEqual(qualification_matrix([{'protocol':'SMB','mountpoint':'relative'}])['report']['rows'][0]['status'],'BLOCKED')
    def test_missing_mount_blocked(self):
        with patch('capability_probe.attest_mount',side_effect=ValueError('missing')):
            self.assertEqual(qualification_matrix([{'protocol':'SMB','mountpoint':'/mnt/smb'}])['report']['rows'][0]['status'],'BLOCKED')
    def test_evidence_never_qualified(self):
        with patch('capability_probe.attest_mount',return_value={'mount_id':'123'}):
            result=qualification_matrix([{'protocol':'NFSv4','mountpoint':'/mnt/nfs'}])
        self.assertEqual(result['report']['rows'][0]['status'],'EVIDENCE_ONLY')
        self.assertFalse(result['report']['production_qualified'])
    def test_deterministic_hash(self):
        a=[{'protocol':'SMB','mountpoint':'/mnt/smb'}]
        with patch('capability_probe.attest_mount',return_value={'mount_id':'123'}):
            self.assertEqual(qualification_matrix(a)['sha256'],qualification_matrix(a)['sha256'])
