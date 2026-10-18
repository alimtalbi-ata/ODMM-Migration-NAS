"""V196.0 bounded HTTPS-only read transport for vendor verification.

No redirects, proxies, writes, retries or implicit credentials. Caller pins TLS trust
via SSLContext and restricts exact host:port via approved_origins.
"""
import http.client
import ipaddress
import ssl
from urllib.parse import urlsplit

class TransportRejected(ValueError):
    pass


def make_https_get_transport(*, approved_origins, ssl_context, timeout=5.0,
                             max_response_bytes=65536, connection_factory=None,
                             require_client_certificate=False, require_json=False,
                             client_certificate_attestor=None):
    if not isinstance(ssl_context, ssl.SSLContext) or ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
        raise TransportRejected('TLS_VERIFICATION_REQUIRED')
    if not isinstance(require_client_certificate, bool) or not isinstance(require_json, bool):
        raise TransportRejected('POLICY_INVALID')
    if require_client_certificate and (not callable(client_certificate_attestor) or client_certificate_attestor(ssl_context) is not True):
        raise TransportRejected('CLIENT_IDENTITY_UNVERIFIED')
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 30:
        raise TransportRejected('TIMEOUT_INVALID')
    if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or not 0 < max_response_bytes <= 1048576:
        raise TransportRejected('RESPONSE_LIMIT_INVALID')
    if not isinstance(approved_origins, (set, frozenset, tuple, list)) or not approved_origins:
        raise TransportRejected('ORIGINS_REQUIRED')

    def validate(url, origin=False):
        if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
            raise TransportRejected('URL_INVALID')
        try:
            parsed = urlsplit(url)
            port = parsed.port or 443
        except ValueError as exc:
            raise TransportRejected('URL_INVALID') from exc
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or port < 1 or port > 65535
                or parsed.hostname.endswith('.') or '%' in parsed.netloc or '\\' in url):
            raise TransportRejected('URL_INVALID')
        if origin and (parsed.path or parsed.query):
            raise TransportRejected('ORIGIN_INVALID')
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise TransportRejected('IP_LITERAL_FORBIDDEN')
        return parsed, (parsed.hostname.lower(), port)

    allowed = set()
    for origin in approved_origins:
        parsed, key = validate(origin, True)
        allowed.add(key)
    factory = connection_factory or (lambda host, port, timeout, context: http.client.HTTPSConnection(host, port, timeout=timeout, context=context))

    def get(url, headers):
        parsed, key = validate(url)
        if key not in allowed:
            raise TransportRejected('ORIGIN_NOT_APPROVED')
        if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) or '\r' in k+v or '\n' in k+v for k,v in headers.items()):
            raise TransportRejected('HEADERS_INVALID')
        # No caller-controlled Host or transfer encoding, no transparent proxy.
        if any(k.lower() in ('host', 'connection', 'transfer-encoding', 'content-length') for k in headers):
            raise TransportRejected('HEADERS_FORBIDDEN')
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        conn = factory(key[0], key[1], timeout, ssl_context)
        try:
            conn.request('GET', path, headers={**headers, 'Connection':'close'})
            response = conn.getresponse()
            status = response.status
            if not isinstance(status, int) or status != 200:
                raise TransportRejected('HTTP_STATUS_REJECTED')
            if require_json:
                media = response.getheader('Content-Type')
                if not isinstance(media, str) or media.split(';', 1)[0].strip().lower() not in ('application/json',) and not (isinstance(media, str) and media.split(';',1)[0].strip().lower().endswith('+json')):
                    raise TransportRejected('JSON_CONTENT_TYPE_REQUIRED')
            content_length = response.getheader('Content-Length')
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise TransportRejected('CONTENT_LENGTH_INVALID') from exc
                if declared < 0 or declared > max_response_bytes:
                    raise TransportRejected('RESPONSE_TOO_LARGE')
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise TransportRejected('RESPONSE_TOO_LARGE')
            return status, body
        finally:
            conn.close()
    return get
