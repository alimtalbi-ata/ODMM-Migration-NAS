"""ODMM V210.3: bounded Vault HA reads, circuit breaker, safe telemetry.
Author: Abdelhalim Talbi. Explicit endpoints only; no automatic cutover.
"""
import threading
import time
from urllib.parse import urlsplit
from odmm_vault_transport_v2101 import VaultHTTPSClient, VaultTransportError, _endpoint

class VaultHAClient:
    """Fail over only idempotent KV reads; AppRole login/renew remain pinned.

    Callers must configure endpoints in the same trusted Vault security domain.
    No retries of POST, renewal or token-changing requests.
    """
    def __init__(self, endpoints, *, client_factory=VaultHTTPSClient, clock=None,
                 failure_threshold=2, cooldown_seconds=30):
        if not isinstance(endpoints, (list, tuple)) or not 1 <= len(endpoints) <= 8:
            raise ValueError('INVALID_HA_ENDPOINTS')
        normalized = [_endpoint(e) for e in endpoints]
        if len(set(normalized)) != len(normalized):
            raise ValueError('DUPLICATE_HA_ENDPOINT')
        if any(urlsplit(e).hostname != urlsplit(normalized[0]).hostname for e in normalized):
            # Avoid leaking AppRole credentials / Vault tokens to unrelated hosts.
            raise ValueError('HA_HOST_MISMATCH')
        if type(failure_threshold) is not int or not 1 <= failure_threshold <= 10:
            raise ValueError('INVALID_FAILURE_THRESHOLD')
        if type(cooldown_seconds) not in (int, float) or not 1 <= cooldown_seconds <= 3600:
            raise ValueError('INVALID_COOLDOWN')
        self._clients = tuple(client_factory(e) for e in normalized)
        self._clock = clock or time.monotonic
        self._threshold, self._cooldown = failure_threshold, cooldown_seconds
        self._failures = [0] * len(normalized)
        self._open_until = [0.0] * len(normalized)
        self._counts = {'requests':0, 'successes':0, 'failures':0, 'failovers':0, 'circuit_rejections':0}
        self._lock = threading.RLock()

    def request(self, path, headers=None, *, payload=None):
        # No replay of authentication, renewal or other non-idempotent operations.
        safe_read = payload is None and isinstance(path, str) and path.startswith('/v1/')
        with self._lock:
            self._counts['requests'] += 1
            now = float(self._clock())
            eligible = [i for i in range(len(self._clients)) if self._open_until[i] <= now]
            if not eligible:
                self._counts['circuit_rejections'] += 1
                raise VaultTransportError()
            if not safe_read:
                eligible = eligible[:1] if eligible[0] == 0 else []
                if not eligible:
                    self._counts['circuit_rejections'] += 1
                    raise VaultTransportError()
            for pos, i in enumerate(eligible):
                try:
                    result = self._clients[i].request(path, headers, payload=payload)
                    self._failures[i] = 0
                    self._open_until[i] = 0.0
                    self._counts['successes'] += 1
                    if pos:
                        self._counts['failovers'] += 1
                    return result
                except Exception:
                    self._counts['failures'] += 1
                    self._failures[i] += 1
                    if self._failures[i] >= self._threshold:
                        self._open_until[i] = now + self._cooldown
                    if not safe_read:
                        break
            raise VaultTransportError() from None

    def status(self):
        with self._lock:
            try:
                now = float(self._clock())
                available = sum(t <= now for t in self._open_until)
            except Exception:
                available = 0
            return {'schema':'odmm.vault.ha.v2103', 'state':'AVAILABLE' if available else 'UNAVAILABLE',
                    'available_endpoints':available, 'configured_endpoints':len(self._clients),
                    'metrics':dict(self._counts), 'cutover_authorized':False}
