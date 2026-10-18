"""V194.6: inspect live ASGI/FastAPI route objects, not caller-supplied manifests.

Run after all routes/mounts have been registered, before serving requests.
Not a replacement for disabling direct Python access to legacy functions.
"""
import hashlib
import json
import re
from native_rotation_entrypoint_policy import GUARDED, LEGACY

_ROTATION = re.compile(r'rotat|epoch|key[_-]?change|key[_-]?switch', re.I)


def inspect_live_routes(app, *, allowed_endpoint, expected_sha256=None):
    """Fail closed on every rotation-like live route except exact approved endpoint.

    `allowed_endpoint` is the actual function object, not a string identifier.
    Mounted sub-apps are recursively inspected; unknown mounts fail closed.
    """
    if not callable(allowed_endpoint) or not hasattr(app, 'routes'):
        raise ValueError('LIVE_ROUTES_INVALID')
    rows, seen_apps, found = [], set(), [0]

    def walk(current, prefix):
        if id(current) in seen_apps:
            raise ValueError('LIVE_ROUTE_CYCLE_OR_DUPLICATE')
        seen_apps.add(id(current))
        routes = getattr(current, 'routes', None)
        if not isinstance(routes, (list, tuple)):
            raise ValueError('LIVE_ROUTES_INVALID')
        for route in routes:
            path = getattr(route, 'path', None)
            if not isinstance(path, str) or not path.startswith('/'):
                raise ValueError('LIVE_ROUTE_INVALID')
            full = prefix + path
            if len(full) > 512:
                raise ValueError('LIVE_ROUTE_INVALID')
            subapp = getattr(route, 'app', None)
            endpoint = getattr(route, 'endpoint', None)
            if endpoint is None and subapp is not None:
                walk(subapp, full.rstrip('/'))
                continue
            if not callable(endpoint):
                raise ValueError('LIVE_ROUTE_ENDPOINT_UNKNOWN')
            name = getattr(endpoint, '__name__', '')
            module = getattr(endpoint, '__module__', '')
            methods = getattr(route, 'methods', None)
            if methods is None:
                raise ValueError('LIVE_ROUTE_METHODS_UNKNOWN')
            if not isinstance(methods, (set, frozenset, list, tuple)) or not methods:
                raise ValueError('LIVE_ROUTE_METHODS_UNKNOWN')
            verbs = sorted(methods)
            if any(not isinstance(m, str) for m in verbs):
                raise ValueError('LIVE_ROUTE_METHODS_UNKNOWN')
            risky = bool(_ROTATION.search(full) or _ROTATION.search(name) or name in LEGACY)
            if endpoint is allowed_endpoint:
                if not risky or not set(verbs).issubset({'POST'}):
                    raise ValueError('GUARDED_ROUTE_NOT_POST')
                found[0] += 1
            elif risky:
                raise ValueError('LIVE_UNGUARDED_ROTATION_ROUTE')
            rows.append({'path': full, 'methods': verbs, 'handler': module + '.' + name,
                         'guarded': endpoint is allowed_endpoint})

    walk(app, '')
    if found[0] != 1:
        raise ValueError('GUARDED_ROUTE_COUNT_INVALID')
    rows.sort(key=lambda r: (r['path'], r['methods']))
    canonical = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
            raise ValueError('LIVE_ROUTE_ANCHOR_INVALID')
        import hmac
        if not hmac.compare_digest(digest, expected_sha256):
            raise ValueError('LIVE_ROUTE_ANCHOR_MISMATCH')
    return {'schema': 'odmm.rotation.live-routes.v1', 'sha256': digest,
            'routes': rows, 'production_qualified': False, 'external_anchor_required': True}
