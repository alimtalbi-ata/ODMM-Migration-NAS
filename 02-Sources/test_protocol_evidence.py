import unittest
from protocol_evidence import normalize_acl_capture,compare_captures,qualification_report
D='a'*64

def sample(side='source',**kw):
    d=dict(protocol='SMB',side=side,path='/share/file',collector='external:v1',identity_context='realm-A',acl_raw_sha256=D,complete=True)
    d.update(kw)
    return d

class ProtocolEvidenceTests(unittest.TestCase):
    def test_complete_capture_is_not_certification(self):
        self.assertFalse(normalize_acl_capture(sample())['effective_access_certified'])
    def test_identical_opaque_is_not_access_equivalence(self):
        r=compare_captures(sample(),sample('target'))
        self.assertEqual(r['status'],'MATCHED_OPAQUE_EVIDENCE')
        self.assertFalse(r['effective_access_certified'])
    def test_different_acl_blocks(self):
        self.assertIn('OPAQUE_ACL_DIFFERENCE',compare_captures(sample(),sample('target',acl_raw_sha256='b'*64))['reasons'])
    def test_incomplete_blocks(self):
        self.assertIn('INCOMPLETE_CAPTURE',compare_captures(sample(complete=False),sample('target'))['reasons'])
    def test_invalid_digest_rejected(self):
        with self.assertRaises(ValueError): normalize_acl_capture(sample(acl_raw_sha256='x'))
    def test_missing_context_rejected(self):
        with self.assertRaises(ValueError): normalize_acl_capture(sample(identity_context=''))
    def test_report_fail_closed(self):
        r=qualification_report([compare_captures(sample(),sample('target'))])
        self.assertEqual(r['status'],'NOT_QUALIFIED')
        self.assertEqual(len(r['report_sha256']),64)
    def test_deterministic_digest(self):
        self.assertEqual(normalize_acl_capture(sample()),normalize_acl_capture(sample()))

if __name__=='__main__': unittest.main()
