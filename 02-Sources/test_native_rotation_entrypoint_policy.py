import unittest
from native_rotation_entrypoint_policy import validate_rotation_routes

GOOD=[{'path':'/api/rotation','handler':'apply_review_gated_rotation','rotation_enabled':True},
      {'path':'/api/legacy','handler':'transact_epoch','rotation_enabled':False}]

class RotationPolicyTests(unittest.TestCase):
    def test_good(self):
        self.assertEqual(validate_rotation_routes(GOOD)['status'],'ADMISSION_READY')
    def test_digest_anchor(self):
        d=validate_rotation_routes(GOOD)['route_manifest_sha256']
        self.assertEqual(validate_rotation_routes(GOOD,expected_manifest_sha256=d)['route_manifest_sha256'],d)
    def test_wrong_anchor(self):
        with self.assertRaises(ValueError):validate_rotation_routes(GOOD,expected_manifest_sha256='0'*64)
    def test_legacy_exposed(self):
        with self.assertRaises(ValueError):validate_rotation_routes([{'path':'/rotate','handler':'transact_epoch','rotation_enabled':True}])
    def test_other_handler(self):
        with self.assertRaises(ValueError):validate_rotation_routes([{'path':'/rotate','handler':'some_other_handler','rotation_enabled':True}])
    def test_duplicate(self):
        with self.assertRaises(ValueError):validate_rotation_routes(GOOD+GOOD)
    def test_no_guarded(self):
        with self.assertRaises(ValueError):validate_rotation_routes([GOOD[1]])
    def test_bad_schema(self):
        with self.assertRaises(ValueError):validate_rotation_routes([{'path':'/x','handler':'apply_review_gated_rotation','rotation_enabled':1}])
    def test_stable_order(self):
        self.assertEqual(validate_rotation_routes(GOOD)['route_manifest_sha256'],validate_rotation_routes(list(reversed(GOOD)))['route_manifest_sha256'])

if __name__=='__main__':unittest.main()
