"""Optional ldap3 LDAPS read-only paged transport, fail closed by default.

Requires: pip install ldap3. This module never changes LDAP directory objects.
Credentials are passed in memory; do not log or serialize them.
"""
import ssl
from urllib.parse import urlparse
from ldap_readonly_adapter import collect_readonly_snapshot, LDAPReadError

class LDAPTransportError(LDAPReadError): pass

class LDAPSReadClient:
    def __init__(self, *, endpoint, bind_dn, password, ca_file, timeout=10, page_size=200, ldap_module=None):
        parsed=urlparse(endpoint)
        if parsed.scheme!='ldaps' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment or parsed.port not in (None,636):
            raise LDAPTransportError('LDAPS_ENDPOINT_REQUIRED')
        if not isinstance(bind_dn,str) or not bind_dn.strip() or not isinstance(password,str) or not password or not isinstance(ca_file,str) or not ca_file.strip():
            raise LDAPTransportError('CREDENTIALS_AND_CA_REQUIRED')
        if type(timeout) not in (int,float) or not 0 < timeout <= 120 or type(page_size) is not int or not 1 <= page_size <= 1000:
            raise LDAPTransportError('INVALID_LIMITS')
        if ldap_module is None:
            try: import ldap3 as ldap_module
            except ImportError as exc: raise LDAPTransportError('LDAP3_DEPENDENCY_MISSING') from exc
        self._ldap=ldap_module
        self._server=ldap_module.Server(parsed.hostname, port=parsed.port or 636, use_ssl=True,
            tls=ldap_module.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file, version=ssl.PROTOCOL_TLS_CLIENT),
            connect_timeout=timeout, get_info=ldap_module.NONE)
        self._bind_dn=bind_dn; self._password=password; self._timeout=timeout; self._page_size=page_size
        self._conn=None

    def __enter__(self):
        try:
            self._conn=self._ldap.Connection(self._server, user=self._bind_dn, password=self._password,
                authentication=self._ldap.SIMPLE, receive_timeout=self._timeout, auto_bind=True,
                raise_exceptions=True, auto_referrals=False)
        except Exception as exc:
            raise LDAPTransportError('TLS_BIND_FAILED') from exc
        return self

    def __exit__(self, *args):
        if self._conn is not None:
            try: self._conn.unbind()
            finally: self._conn=None

    def search(self, base, filter, attributes, cookie):
        if self._conn is None: raise LDAPTransportError('NOT_BOUND')
        try:
            ok=self._conn.search(search_base=base, search_filter=filter,
                search_scope=self._ldap.SUBTREE, attributes=list(attributes),
                paged_size=self._page_size, paged_cookie=cookie)
            if not ok: raise LDAPTransportError('LDAP_SEARCH_FAILED')
            entries=[]
            for item in self._conn.response:
                if item.get('type')!='searchResEntry': continue
                raw=item.get('attributes',{})
                def scalar(key):
                    value=raw.get(key)
                    if isinstance(value,list): return value[0] if len(value)==1 else value
                    return value
                groups=raw.get('memberOf',[])
                if isinstance(groups,str): groups=[groups]
                entries.append({'entryUUID':scalar('entryUUID'), 'uid':scalar('uid'),
                    'userAccountControl':scalar('userAccountControl'), 'memberOf':groups})
            controls=self._conn.result.get('controls',{})
            ctrl=controls.get('1.2.840.113556.1.4.319',{}).get('value',{})
            nxt=ctrl.get('cookie')
            if isinstance(nxt,bytes): nxt=nxt.decode('latin1')
            if nxt == '': nxt=None
            return {'entries':entries,'next_cookie':nxt,'complete':not bool(nxt)}
        except LDAPTransportError: raise
        except Exception as exc: raise LDAPTransportError('LDAP_SEARCH_FAILED') from exc

def collect_ldaps_snapshot(*, endpoint, base_dn, version, bind_dn, password, ca_file, timeout=10, page_size=200, max_pages=100, ldap_module=None):
    with LDAPSReadClient(endpoint=endpoint,bind_dn=bind_dn,password=password,ca_file=ca_file,
                         timeout=timeout,page_size=page_size,ldap_module=ldap_module) as client:
        result=collect_readonly_snapshot(endpoint=endpoint,base_dn=base_dn,version=version,client=client,max_pages=max_pages)
    result['transport']='LDAPS_TLS_CA_VALIDATED_BY_CLIENT'
    # A successful TLS bind does not prove authoritative directory data or reviewer identity.
    result['authenticated']=False
    result['cutover_authorized']=False
    return result
