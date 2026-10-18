"""V187.4: read-only remote witness verifier over mutually authenticated TLS.

The endpoint is an independent operator-managed service. No publication or
repair API is exposed. Server replies are HMAC authenticated and nonce bound;
TLS client authentication and certificate validation are mandatory.
"""
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import time
from ldaps_ipc_persistent_identity import IdentityPinError


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class RemoteWitnessVerifier:
    def __init__(self, *, host, port, cafile, certfile, keyfile, witness_key,
                 server_name=None, timeout=3.0, transport=None):
        if not isinstance(witness_key, bytes) or len(witness_key) < 32:
            raise IdentityPinError('REMOTE_WITNESS_KEY_TOO_SHORT')
        if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
            raise IdentityPinError('REMOTE_WITNESS_ENDPOINT_INVALID')
        if not all(isinstance(p, str) and p for p in (cafile, certfile, keyfile)):
            raise IdentityPinError('REMOTE_WITNESS_MTLS_REQUIRED')
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 30:
            raise IdentityPinError('REMOTE_WITNESS_TIMEOUT_INVALID')
        self.host, self.port, self.server_name = host, port, server_name or host
        self.cafile, self.certfile, self.keyfile = cafile, certfile, keyfile
        self.key, self.timeout, self.transport = witness_key, timeout, transport

    def _exchange(self, payload):
        if self.transport is not None:
            return self.transport(payload)
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_cert_chain(self.certfile, self.keyfile)
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=self.server_name) as conn:
                conn.settimeout(self.timeout)
                conn.sendall(canonical(payload) + b'\n')
                data = bytearray()
                while len(data) <= 16384:
                    part = conn.recv(min(4096, 16385 - len(data)))
                    if not part:
                        break
                    data.extend(part)
                    if b'\n' in part:
                        break
                if len(data) > 16384 or b'\n' not in data:
                    raise IdentityPinError('REMOTE_WITNESS_RESPONSE_INVALID')
                return json.loads(bytes(data).split(b'\n', 1)[0])

    def verify(self, *, expected_count, expected_last_mac):
        if (type(expected_count) is not int or expected_count < 0 or
                not isinstance(expected_last_mac, str) or len(expected_last_mac) != 64 or
                any(c not in '0123456789abcdef' for c in expected_last_mac)):
            raise IdentityPinError('REMOTE_WITNESS_EXPECTATION_INVALID')
        nonce = secrets.token_hex(32)
        request = {'version': 1, 'action': 'read', 'nonce': nonce}
        try:
            reply = self._exchange(request)
        except (OSError, ssl.SSLError, ValueError, TimeoutError) as exc:
            raise IdentityPinError('REMOTE_WITNESS_UNAVAILABLE') from exc
        if not isinstance(reply, dict) or set(reply) != {'version', 'nonce', 'count', 'last_mac', 'hmac_sha256'}:
            raise IdentityPinError('REMOTE_WITNESS_RESPONSE_INVALID')
        body = {k: reply[k] for k in ('version', 'nonce', 'count', 'last_mac')}
        if (body['version'] != 1 or type(body['count']) is not int or body['count'] < 0 or
                body['nonce'] != nonce or not isinstance(body['last_mac'], str) or
                len(body['last_mac']) != 64 or not isinstance(reply['hmac_sha256'], str)):
            raise IdentityPinError('REMOTE_WITNESS_RESPONSE_INVALID')
        mac = hmac.new(self.key, canonical(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, reply['hmac_sha256']):
            raise IdentityPinError('REMOTE_WITNESS_AUTH_FAILED')
        if (body['count'], body['last_mac']) != (expected_count, expected_last_mac):
            raise IdentityPinError('REMOTE_WITNESS_DIVERGENCE_MANUAL_REVIEW')
        return {'status': 'REMOTE_WITNESS_VERIFIED', 'count': body['count'],
                'recovery_authorized': False, 'cutover_authorized': False}
