"""Controlled, offline JWKS rotation for ODMM review. Author: Abdelhalim Talbi.

Never retrieves keys from untrusted tokens or the network. Rotation requires an
operator-supplied, independently authenticated JWKS document.
"""
import hashlib
import json
import threading
from odmm_oidc_verifier import OIDCVerifier


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def jwks_digest(jwks):
    return hashlib.sha256(_canonical(jwks)).hexdigest()


class PinnedJWKSRotation:
    def __init__(self, *, issuer, audience, jwks, role_claim='roles', allowed_roles=None, clock=None):
        self._lock = threading.RLock()
        self._settings = dict(issuer=issuer, audience=audience, role_claim=role_claim,
                              allowed_roles=allowed_roles, clock=clock)
        self._verifier = OIDCVerifier(jwks=jwks, **self._settings)
        self._digest = jwks_digest(jwks)
        self._generation = 0

    @property
    def state(self):
        with self._lock:
            return {'generation': self._generation, 'jwks_sha256': self._digest,
                    'key_count': len(self._verifier.keys)}

    def verify(self, token):
        with self._lock:
            verifier = self._verifier
        return verifier.verify(token)

    def resolve_request(self, request):
        with self._lock:
            verifier = self._verifier
        return verifier.resolve_request(request)

    def rotate(self, *, jwks, expected_generation, expected_sha256, expected_previous_sha256,
               require_overlap=True):
        """CAS update; reject key drops during overlap. All checks precede swap."""
        if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
            raise ValueError('GENERATION_INVALID')
        if not isinstance(expected_sha256, str) or jwks_digest(jwks) != expected_sha256:
            raise ValueError('JWKS_DIGEST_MISMATCH')
        candidate = OIDCVerifier(jwks=jwks, **self._settings)
        with self._lock:
            if expected_generation != self._generation or expected_previous_sha256 != self._digest:
                raise ValueError('JWKS_ROTATION_STALE')
            old_keys = self._verifier.keys
            if require_overlap and not set(old_keys).issubset(candidate.keys):
                raise ValueError('JWKS_OVERLAP_REQUIRED')
            # Reusing a kid with a different key would silently change trust.
            for kid in set(old_keys).intersection(candidate.keys):
                if old_keys[kid].public_numbers() != candidate.keys[kid].public_numbers():
                    raise ValueError('JWKS_KID_REUSE')
            if self._digest == expected_sha256:
                raise ValueError('JWKS_ROTATION_NO_CHANGE')
            self._verifier = candidate
            self._digest = expected_sha256
            self._generation += 1
            return self.state
