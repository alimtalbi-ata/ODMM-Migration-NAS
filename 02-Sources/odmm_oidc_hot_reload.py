"""V197.8: fail-closed on-demand pinned JWKS hot reload, no network access."""
import json
import os
import stat
import threading
import time
from pathlib import Path
from odmm_oidc_verifier import OIDCVerifier

class ReloadingOIDCVerifier:
    def __init__(self, *, issuer, audience, jwks_path, role_claim='roles', check_interval=0.0, clock=None):
        self.path = Path(jwks_path)
        self.issuer, self.audience, self.role_claim = issuer, audience, role_claim
        if not isinstance(check_interval, (int, float)) or not 0 <= check_interval <= 5:
            raise ValueError('INVALID_JWKS_CHECK_INTERVAL')
        self._interval = float(check_interval)
        self._clock = clock or time.monotonic
        self._next_check = 0.0
        self._lock = threading.RLock()
        self._fingerprint = None
        self._verifier = None
        self.reload(force=True)

    def _read(self):
        if self.path.is_symlink():
            raise PermissionError('JWKS_SYMLINK_FORBIDDEN')
        fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or (os.name == 'posix' and st.st_mode & 0o022):
                raise PermissionError('JWKS_UNSAFE_FILE')
            if st.st_size > 1024 * 1024:
                raise PermissionError('JWKS_TOO_LARGE')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                content = stream.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise PermissionError('JWKS_TOO_LARGE')
            return content
        finally:
            os.close(fd)

    def reload(self, force=False):
        import hashlib
        with self._lock:
            try:
                raw = self._read()
                fingerprint = hashlib.sha256(raw).digest()
                if not force and fingerprint == self._fingerprint:
                    self._next_check = self._clock() + self._interval
                    return False
                jwks = json.loads(raw)
                candidate = OIDCVerifier(issuer=self.issuer, audience=self.audience,
                                         jwks=jwks, role_claim=self.role_claim)
                # The operator must rotate via an approved, pinned file; never fetch token URLs.
                self._verifier = candidate
                self._fingerprint = fingerprint
                self._next_check = self._clock() + self._interval
                return True
            except Exception as exc:
                # Never keep using old keys when trusted on-disk state is unreadable or invalid.
                self._verifier = None
                self._fingerprint = None
                self._next_check = 0.0
                raise PermissionError('JWKS_RELOAD_FAILED') from exc

    def verify(self, token):
        with self._lock:
            if self._interval == 0 or self._clock() >= self._next_check:
                self.reload()
            return self._verifier.verify(token)

    def resolve_request(self, request):
        auth = request.headers.get('authorization', '')
        if not isinstance(auth, str) or not auth.startswith('Bearer ') or auth.count(' ') != 1:
            raise PermissionError('BEARER_REQUIRED')
        return self.verify(auth[7:])
