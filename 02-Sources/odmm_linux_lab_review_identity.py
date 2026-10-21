"""Short-lived HMAC assertions for isolated Linux review laboratory.

The shared secret must come from a trusted issuer, never the request itself.
Not a replacement for OIDC, mTLS or an independent identity provider.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import time
from odmm_linux_datamover_intents import _id

class IdentityDenied(PermissionError):
    pass

def _message(operator_id, role, issued_at, expires_at):
    return json.dumps({"operator_id": operator_id, "role": role,
                       "issued_at": issued_at, "expires_at": expires_at},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")

def issue_assertion(secret, *, operator_id, role, issued_at, ttl=300):
    """Trusted issuer only; never expose this function on an unauthenticated API."""
    operator_id, role = _id(operator_id), _id(role)
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("WEAK_SIGNING_SECRET")
    if type(issued_at) is not int or issued_at < 0 or type(ttl) is not int or not 1 <= ttl <= 900:
        raise ValueError("INVALID_ASSERTION_LIFETIME")
    expires_at = issued_at + ttl
    signature = hmac.new(secret, _message(operator_id, role, issued_at, expires_at),
                         hashlib.sha256).hexdigest()
    return {"operator_id": operator_id, "role": role, "issued_at": issued_at,
            "expires_at": expires_at, "signature": signature}

def verify_assertion(secret, assertion, *, now=None):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise IdentityDenied("UNTRUSTED_SIGNING_KEY")
    if not isinstance(assertion, dict) or set(assertion) != {"operator_id", "role", "issued_at", "expires_at", "signature"}:
        raise IdentityDenied("INVALID_ASSERTION")
    try:
        operator_id = _id(assertion["operator_id"])
        role = _id(assertion["role"])
    except ValueError as exc:
        raise IdentityDenied("INVALID_IDENTITY") from exc
    issued_at, expires_at = assertion["issued_at"], assertion["expires_at"]
    if type(issued_at) is not int or type(expires_at) is not int or not 1 <= expires_at - issued_at <= 900:
        raise IdentityDenied("INVALID_ASSERTION_LIFETIME")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < issued_at or now >= expires_at:
        raise IdentityDenied("EXPIRED_OR_FUTURE_ASSERTION")
    signature = assertion["signature"]
    if not isinstance(signature, str) or len(signature) != 64:
        raise IdentityDenied("INVALID_SIGNATURE")
    expected = hmac.new(secret, _message(operator_id, role, issued_at, expires_at),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise IdentityDenied("SIGNATURE_MISMATCH")
    return {"operator_id": operator_id, "role": role, "identity_verified": True}
