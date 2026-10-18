"""V195.8: opt-in production route lockdown, deny unknown handler aliases.

This is an ASGI route admission policy, not a Python sandbox. The deployment
must pin the allowed non-rotation routes out of band; never derive policy from
untrusted runtime routes during startup.
"""
import hashlib
import hmac
import json
import re
from native_rotation_live_route_gate import inspect_live_routes

_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def verify_production_routes(app, *, rotation_endpoint, allowed_routes, trusted_policy_sha256,
                             trusted_routes_sha256):
    """Verify exact path, method and callable identity for every exposed route.

    allowed_routes: iterable of (path, methods, callable) for non-rotation routes.
    An independent deployment manifest must pin both policy and live route hashes.
    """
    if not isinstance(trusted_policy_sha256,str) or not _DIGEST.fullmatch(trusted_policy_sha256):
        raise ValueError('PRODUCTION_POLICY_ANCHOR_REQUIRED')
    if not isinstance(trusted_routes_sha256,str) or not _DIGEST.fullmatch(trusted_routes_sha256):
        raise ValueError('PRODUCTION_ROUTE_ANCHOR_REQUIRED')
    if not isinstance(allowed_routes,(list,tuple)):
        raise ValueError('PRODUCTION_ALLOWLIST_REQUIRED')
    approved = {}
    for path, methods, endpoint in allowed_routes:
        if not isinstance(path,str) or not path.startswith('/') or not callable(endpoint):
            raise ValueError('PRODUCTION_ALLOWLIST_INVALID')
        if not isinstance(methods,(tuple,list,set,frozenset)) or not methods or any(not isinstance(x,str) for x in methods):
            raise ValueError('PRODUCTION_ALLOWLIST_INVALID')
        key=(path,tuple(sorted(methods)))
        if key in approved or endpoint is rotation_endpoint:
            raise ValueError('PRODUCTION_ALLOWLIST_DUPLICATE')
        approved[key]=endpoint
    policy_rows=sorted([{'path':p,'methods':list(m),'handler':f'{e.__module__}.{e.__qualname__}'} for (p,m),e in approved.items()],key=lambda r:(r['path'],r['methods']))
    policy_hash=hashlib.sha256(json.dumps(policy_rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if not hmac.compare_digest(policy_hash,trusted_policy_sha256):
        raise ValueError('PRODUCTION_POLICY_ANCHOR_MISMATCH')
    report=inspect_live_routes(app,allowed_endpoint=rotation_endpoint,expected_sha256=trusted_routes_sha256)
    observed={}
    def walk(current,prefix=''):
        for route in current.routes:
            path=prefix+route.path
            endpoint=getattr(route,'endpoint',None)
            if endpoint is None and getattr(route,'app',None) is not None:
                walk(route.app,path.rstrip('/'))
                continue
            key=(path,tuple(sorted(route.methods)))
            if key in observed:
                raise ValueError('PRODUCTION_DUPLICATE_ROUTE')
            observed[key]=endpoint
    walk(app)
    expected={**approved,('/api/v1/security/rotation',('POST',)):rotation_endpoint}
    if set(observed)!=set(expected) or any(observed[k] is not expected[k] for k in expected):
        raise ValueError('PRODUCTION_UNAPPROVED_ROUTE_OR_HANDLER')
    return {'admitted':True,'policy_sha256':policy_hash,'routes_sha256':report['sha256'],
            'production_qualified':False}


def production_policy_digest(allowed_routes):
    """Offline deployment planning helper; its output must be independently pinned."""
    rows=sorted([{'path':p,'methods':sorted(m),'handler':f'{e.__module__}.{e.__qualname__}'} for p,m,e in allowed_routes],key=lambda r:(r['path'],r['methods']))
    return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
