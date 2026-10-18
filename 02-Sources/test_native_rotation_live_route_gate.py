import unittest
from types import SimpleNamespace as NS
from native_rotation_live_route_gate import inspect_live_routes


def guarded(): pass
def health(): pass
def rotate_legacy(): pass

def route(path, endpoint, methods=('POST',)):
    return NS(path=path, endpoint=endpoint, methods=set(methods))

class LiveRoutesTest(unittest.TestCase):
    def app(self, *routes): return NS(routes=list(routes))
    def test_good(self):
        a=self.app(route('/health',health,('GET',)),route('/api/rotate',guarded))
        result=inspect_live_routes(a,allowed_endpoint=guarded)
        self.assertEqual(2,len(result['routes']))
        self.assertEqual(result['sha256'],inspect_live_routes(a,allowed_endpoint=guarded,expected_sha256=result['sha256'])['sha256'])
    def test_legacy_path(self):
        with self.assertRaisesRegex(ValueError,'UNGUARDED'):
            inspect_live_routes(self.app(route('/rotate',guarded),route('/old/epoch',health)),allowed_endpoint=guarded)
    def test_legacy_name(self):
        with self.assertRaisesRegex(ValueError,'UNGUARDED'):
            inspect_live_routes(self.app(route('/rotate',guarded),route('/old',rotate_legacy)),allowed_endpoint=guarded)
    def test_get_guarded(self):
        with self.assertRaisesRegex(ValueError,'NOT_POST'):
            inspect_live_routes(self.app(route('/rotate',guarded,('GET',))),allowed_endpoint=guarded)
    def test_missing_guarded(self):
        with self.assertRaisesRegex(ValueError,'COUNT'):
            inspect_live_routes(self.app(route('/health',health,('GET',))),allowed_endpoint=guarded)
    def test_duplicate_guarded(self):
        with self.assertRaisesRegex(ValueError,'COUNT'):
            inspect_live_routes(self.app(route('/rotate',guarded),route('/rotate2',guarded)),allowed_endpoint=guarded)
    def test_anchor(self):
        with self.assertRaisesRegex(ValueError,'ANCHOR_MISMATCH'):
            inspect_live_routes(self.app(route('/rotate',guarded)),allowed_endpoint=guarded,expected_sha256='0'*64)
    def test_mount(self):
        sub=self.app(route('/rotate',guarded))
        root=self.app(NS(path='/api',endpoint=None,app=sub))
        self.assertEqual('/api/rotate',inspect_live_routes(root,allowed_endpoint=guarded)['routes'][0]['path'])
    def test_mount_cycle(self):
        root=self.app();root.routes.append(NS(path='/api',endpoint=None,app=root))
        with self.assertRaisesRegex(ValueError,'CYCLE'):
            inspect_live_routes(root,allowed_endpoint=guarded)
    def test_unknown_endpoint(self):
        with self.assertRaisesRegex(ValueError,'UNKNOWN'):
            inspect_live_routes(self.app(NS(path='/unknown',endpoint=None,app=None)),allowed_endpoint=guarded)
