"""V198.1 Full/Compact OIDC session boundary policy. Author: Abdelhalim Talbi.
Pure policy functions; no modification to the native data mover.
"""
import hmac
from urllib.parse import urlsplit

SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

def validate_origin(origin, expected_origin):
    """Require an exact HTTPS origin (no path, credentials or default-port alias)."""
    if not isinstance(origin, str) or not isinstance(expected_origin, str):
        raise PermissionError('ORIGIN_REQUIRED')
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or origin != expected_origin):
        raise PermissionError('ORIGIN_REJECTED')
    return True

def require_csrf(*, method, origin, expected_origin, cookie_token, submitted_token):
    """Call for every cookie-authenticated state-changing HTTP operation.
    Do not exempt logout or use this as a substitute for authorization/RBAC.
    """
    if not isinstance(method, str) or method.upper() not in SAFE_METHODS:
        validate_origin(origin, expected_origin)
        if (not isinstance(cookie_token, str) or not isinstance(submitted_token, str)
                or len(cookie_token) < 32 or len(cookie_token) > 256
                or len(submitted_token) != len(cookie_token)
                or not hmac.compare_digest(cookie_token, submitted_token)):
            raise PermissionError('CSRF_REJECTED')
    return True

def require_fresh_session(*, issued_at, expires_at, now, max_age=900):
    if (not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (issued_at, expires_at, now))
            or not 0 < max_age <= 3600 or issued_at > now or expires_at <= now
            or now - issued_at > max_age):
        raise PermissionError('SESSION_EXPIRED')
    return True
