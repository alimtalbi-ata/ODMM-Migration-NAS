import os
import tempfile
import unittest
from pathlib import Path
from odmm_native_secure_v2120 import SecureStaging, Blocked
from odmm_native_ownership_v2122 import OwnershipRegistry
from odmm_native_owned_stage_v2123 import OwnedStaging
from odmm_native_metadata_gate_v2125 import MetadataGatedStaging
from odmm_native_metadata_evidence_v2126 import EvidenceGatedStaging, verify_evidence_seal

class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); r=Path(self.tmp.name)
        self.src=r/'src'; self.dst=r/'dst'; self.src.mkdir(); self.dst.mkdir()
        self.registry=OwnershipRegistry(r/'registry.db')
        self.staging=SecureStaging(self.src,self.dst,r/'journal.db')
        self.claim=self.registry.claim('migration','worker',ttl_ns=30_000_000_000)
        self.gate=EvidenceGatedStaging(MetadataGatedStaging(OwnedStaging(self.staging,self.registry,self.claim)))
    def tearDown(self):
        self.staging.close(); self.registry.close(); self.tmp.cleanup()
    def source(self, data=b'payload', mode=0o600):
        p=self.src/'file'; p.write_bytes(data); p.chmod(mode); return p
    def test_evidence_and_seal(self):
        self.source(); proof=self.gate.stage('file')
        self.assertTrue(verify_evidence_seal(proof))
        self.assertEqual(proof['source']['sha256'],proof['target']['sha256'])
        self.assertFalse(proof['cutover_authorized'])
        self.assertFalse(proof['acl_fidelity_verified'])
        self.assertEqual(proof['target']['mode'],0o600)
    def test_tamper_seal(self):
        self.source(); proof=self.gate.stage('file'); proof['target']['size']=999
        self.assertFalse(verify_evidence_seal(proof))
    def test_reject_mode(self):
        self.source(mode=0o640)
        with self.assertRaises(Blocked): self.gate.stage('file')
        self.assertFalse((self.dst/'file').exists())
    def test_reject_stale_owner(self):
        self.source(); self.registry.release(self.claim)
        with self.assertRaises(Blocked): self.gate.stage('file')
    def test_reject_target_exists(self):
        self.source(); (self.dst/'file').write_bytes(b'untouched')
        with self.assertRaises(Blocked): self.gate.stage('file')
        self.assertEqual((self.dst/'file').read_bytes(),b'untouched')
    def test_reject_xattr(self):
        p=self.source()
        try: os.setxattr(p,'user.odmm_test',b'x')
        except (AttributeError,OSError): self.skipTest('xattr unavailable')
        with self.assertRaises(Blocked): self.gate.stage('file')
    def test_reject_traversal(self):
        with self.assertRaises(Blocked): self.gate.stage('../file')
    def test_reject_symlink(self):
        self.source(); (self.src/'link').symlink_to('file')
        with self.assertRaises(OSError): self.gate.stage('link')
    def test_reject_hardlink(self):
        p=self.source(); os.link(p,self.src/'other')
        with self.assertRaises(Blocked): self.gate.stage('file')

if __name__=='__main__': unittest.main()
