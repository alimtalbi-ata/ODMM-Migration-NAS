"""Read-only LDAP3 transport for V219.2 collector. Author: Abdelhalim Talbi.
No credentials are logged or embedded in reports; TLS validation is mandatory.
"""
import ssl
from urllib.parse import urlparse
from odmm_ldap_membership_v2192 import collect_memberships, MembershipCollectionError

class TransportError(ValueError):
    pass

class _PagedClient:
    def __init__(self, connection, page_size):
        self.connection, self.page_size = connection, page_size

    def search(self, *, base, filter, attributes, cookie):
        try:
            SUBTREE = 2  # ldap3.SUBTREE constant; avoid importing dependency in injected tests
            ok = self.connection.search(search_base=base, search_filter=filter,
                search_scope=SUBTREE, attributes=list(attributes), paged_size=self.page_size,
                paged_cookie=cookie or None)
            if not ok and self.connection.result.get('result') != 0:
                raise TransportError('LDAP_SEARCH_FAILED')
            entries = []
            for item in self.connection.response:
                if item.get('type') != 'searchResEntry':
                    continue
                attrs = item.get('attributes') or {}
                normalized = dict(attrs)
                normalized['distinguishedName'] = item.get('dn')
                for field in ('objectClass', 'memberOf', 'member'):
                    val = normalized.get(field, [])
                    normalized[field] = val if isinstance(val, list) else ([val] if val else [])
                uuid = normalized.get('entryUUID')
                if isinstance(uuid, bytes):
                    normalized['entryUUID'] = uuid.hex()
                entries.append(normalized)
            controls = self.connection.result.get('controls') or {}
            page_control = controls.get('1.2.840.113556.1.4.319', {})
            next_cookie = (page_control.get('value') or {}).get('cookie') or None
            return {'entries': entries, 'next_cookie': next_cookie, 'complete': not bool(next_cookie)}
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError('LDAP_SEARCH_FAILED') from exc

def collect_authenticated_memberships(*, endpoint, base_dn, bind_dn, password,
                                      ca_file=None, page_size=200, timeout=10,
                                      connection_factory=None):
    parsed = urlparse(endpoint)
    if (parsed.scheme != 'ldaps' or not parsed.hostname or parsed.username or parsed.password
        or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.port not in (None, 636)):
        raise TransportError('STRICT_LDAPS_REQUIRED')
    if not isinstance(bind_dn, str) or not bind_dn.strip() or not isinstance(password, str) or not password:
        raise TransportError('BIND_CREDENTIALS_REQUIRED')
    if type(page_size) is not int or not 1 <= page_size <= 1000 or type(timeout) not in (int, float) or not 1 <= timeout <= 60:
        raise TransportError('INVALID_LIMITS')
    try:
        if connection_factory is None:
            import ldap3
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file,
                            version=ssl.PROTOCOL_TLS_CLIENT)
            server = ldap3.Server(parsed.hostname, port=636, use_ssl=True, tls=tls,
                                  connect_timeout=timeout, get_info=ldap3.NONE)
            connection = ldap3.Connection(server, user=bind_dn, password=password,
                                          auto_bind=True, receive_timeout=timeout,
                                          raise_exceptions=True, read_only=True)
        else:
            # Injected factories are for tests; never treat them as verified transport.
            connection = connection_factory(parsed.hostname, bind_dn, password)
        try:
            result = collect_memberships(endpoint=endpoint, base_dn=base_dn,
                                         client=_PagedClient(connection, page_size))
            result['report']['transport_authenticated'] = connection_factory is None
            result['report']['transport_mode'] = 'LDAPS_CERT_REQUIRED' if connection_factory is None else 'INJECTED_TEST_CONNECTION'
            result['report']['directory_authenticated'] = False if connection_factory is not None else True
            result['report']['cutover_authorized'] = False
            from odmm_ldap_membership_v2192 import _hash
            result['sha256'] = _hash(result['report'])
            return result
        finally:
            connection.unbind()
    except (MembershipCollectionError, TransportError):
        raise
    except Exception as exc:
        raise TransportError('LDAP_BIND_OR_TLS_FAILED') from exc
