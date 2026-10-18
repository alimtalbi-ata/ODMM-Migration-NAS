"""ODMM V210.2: bounded Vault AppRole session, renewal and health alerts.
Author: Abdelhalim Talbi. No key rotation, cutover or secret persistence.
"""
import threading
import time
from odmm_vault_transport_v2101 import VaultTransportError

class VaultSession:
    """In-memory AppRole token with bounded lifetime and optional renewal.

    No token is returned by status(); errors never include tokens or Vault bodies.
    Client must be a TLS-verified VaultHTTPSClient or equivalent trusted transport.
    """
    def __init__(self, client, *, role_id_provider, secret_id_provider, clock=None,
                 renew_margin=30, max_ttl=3600):
        if not hasattr(client, 'request') or not callable(role_id_provider) or not callable(secret_id_provider):
            raise ValueError('INVALID_SESSION_CONFIGURATION')
        if not isinstance(renew_margin, int) or isinstance(renew_margin, bool) or renew_margin < 0 or renew_margin > 600:
            raise ValueError('INVALID_RENEW_MARGIN')
        if not isinstance(max_ttl, int) or isinstance(max_ttl, bool) or not 1 <= max_ttl <= 86400:
            raise ValueError('INVALID_MAX_TTL')
        self._client, self._role, self._secret = client, role_id_provider, secret_id_provider
        self._clock, self._margin, self._max_ttl = clock or time.monotonic, renew_margin, max_ttl
        self._lock = threading.RLock()
        self._token = None
        self._expires = 0.0
        self._renewable = False
        self._last_action = 'NONE'

    def _install(self, auth, now, action):
        if not isinstance(auth, dict):
            raise VaultTransportError()
        token = auth.get('client_token')
        ttl = auth.get('lease_duration')
        renewable = auth.get('renewable')
        if (not isinstance(token, str) or not token.strip() or not isinstance(ttl, int)
                or isinstance(ttl, bool) or not 0 < ttl <= self._max_ttl
                or not isinstance(renewable, bool)):
            raise VaultTransportError()
        self._token, self._expires, self._renewable = token, now + ttl, renewable
        self._last_action = action

    def _login(self, now):
        role, secret = self._role(), self._secret()
        if not isinstance(role, str) or not role.strip() or not isinstance(secret, str) or not secret.strip():
            raise VaultTransportError()
        response = self._client.request('/v1/auth/approle/login', payload={'role_id': role, 'secret_id': secret})
        self._install(response['auth'], now, 'LOGIN')

    def __call__(self):
        with self._lock:
            try:
                now = float(self._clock())
                if self._token is not None and now < self._expires and self._expires - now > self._margin:
                    return self._token
                if self._token is not None and self._renewable and now < self._expires:
                    try:
                        response = self._client.request('/v1/auth/token/renew-self',
                                                        headers={'X-Vault-Token': self._token}, payload={})
                        self._install(response['auth'], float(self._clock()), 'RENEW')
                        return self._token
                    except Exception:
                        # Renewal failure: discard old token and reauthenticate, never silently reuse.
                        self._token, self._expires, self._renewable = None, 0.0, False
                self._login(float(self._clock()))
                return self._token
            except Exception:
                self._token, self._expires, self._renewable = None, 0.0, False
                self._last_action = 'UNAVAILABLE'
                raise VaultTransportError() from None

    def status(self):
        with self._lock:
            try:
                remaining = max(0, int(self._expires - float(self._clock()))) if self._token else 0
            except Exception:
                remaining = 0
            state = ('UNAVAILABLE' if not remaining else
                     'EXPIRING' if remaining <= self._margin else 'ACTIVE')
            return {'schema':'odmm.vault.session.v2102', 'state':state,
                    'ttl_remaining_seconds':remaining, 'renewable':bool(self._renewable and remaining),
                    'last_action':self._last_action, 'cutover_authorized':False}

    def invalidate(self):
        with self._lock:
            self._token, self._expires, self._renewable = None, 0.0, False
            self._last_action = 'INVALIDATED'


def create_managed_vault_resolver(base_url, *, role_id_provider, secret_id_provider,
                                  mount='secret', prefix='odmm/hmac', ca_file=None,
                                  timeout=5.0, opener=None, clock=None, renew_margin=30):
    """Create Vault KV2 resolver + managed session, for explicit health monitoring."""
    from odmm_vault_transport_v2101 import VaultHTTPSClient
    from odmm_vault_v2100 import VaultKV2Resolver
    client = VaultHTTPSClient(base_url, ca_file=ca_file, timeout=timeout, opener=opener)
    session = VaultSession(client, role_id_provider=role_id_provider,
                           secret_id_provider=secret_id_provider, clock=clock, renew_margin=renew_margin)
    resolver = VaultKV2Resolver(client=client, token_provider=session, mount=mount, prefix=prefix)
    return resolver, session
