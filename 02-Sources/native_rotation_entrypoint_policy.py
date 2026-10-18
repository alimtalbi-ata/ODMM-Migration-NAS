"""V194.0: fail-closed deployment admission for epoch rotation API routes.

This is a deployment gate, not a substitute for firewall, authentication, or
removal of legacy entrypoints. It rejects deployments exposing unsafe routes.
"""
import hashlib
import hmac
import json

GUARDED = 'apply_review_gated_rotation'
LEGACY = frozenset({'transact_epoch', 'rotate_authenticated', 'apply_approved_rotation'})


def validate_rotation_routes(routes, *, expected_manifest_sha256=None):
    """Validate an exact list of externally callable rotation handlers.

    Every handler marked as capable of rotation must use the guarded entrypoint.
    The returned digest must be anchored outside the deployment to prevent a
    modified route manifest from being substituted.
    """
    if not isinstance(routes, list) or not routes:
        raise ValueError('ROTATION_ROUTES_REQUIRED')
    normalized = []
    seen = set()
    for route in routes:
        if not isinstance(route, dict) or set(route) != {'path', 'handler', 'rotation_enabled'}:
            raise ValueError('ROTATION_ROUTE_INVALID')
        path, handler, enabled = route['path'], route['handler'], route['rotation_enabled']
        if (not isinstance(path, str) or not path.startswith('/') or len(path) > 256 or
                not isinstance(handler, str) or not handler or len(handler) > 128 or
                type(enabled) is not bool or path in seen):
            raise ValueError('ROTATION_ROUTE_INVALID')
        seen.add(path)
        if enabled and handler != GUARDED:
            raise ValueError('UNGUARDED_ROTATION_ENTRYPOINT')
        if handler in LEGACY and enabled:
            raise ValueError('LEGACY_ROTATION_EXPOSED')
        normalized.append({'path': path, 'handler': handler, 'rotation_enabled': enabled})
    if not any(r['rotation_enabled'] for r in normalized):
        raise ValueError('NO_GUARDED_ROTATION_ROUTE')
    normalized.sort(key=lambda r: r['path'])
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if expected_manifest_sha256 is not None:
        if (not isinstance(expected_manifest_sha256, str) or len(expected_manifest_sha256) != 64 or
                not hmac.compare_digest(digest, expected_manifest_sha256)):
            raise ValueError('ROTATION_ROUTE_MANIFEST_MISMATCH')
    return {'schema': 'odmm.rotation.routes.v1', 'status': 'ADMISSION_READY',
            'route_manifest_sha256': digest, 'external_attestation_required': True,
            'production_qualified': False, 'cutover_authorized': False}
