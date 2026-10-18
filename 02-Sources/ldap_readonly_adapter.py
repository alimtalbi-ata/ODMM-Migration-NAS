"""Read-only LDAP/AD connector with injectable search client; no cutover authority.

The client must expose search(base, filter, attributes, cookie) -> mapping with
entries, next_cookie, complete. Real network integration requires a separately
configured, TLS-validating LDAP client. Never binds or writes itself.
"""
from urllib.parse import urlparse
from directory_snapshot_adapter import normalize_directory_export

class LDAPReadError(ValueError): pass

ATTRS = ('entryUUID', 'uid', 'userAccountControl', 'memberOf')
GROUPS = {'CN=ODMM_SECURITY_REVIEWERS': 'ODMM_SECURITY_REVIEWERS',
          'CN=ODMM_OPERATIONS_REVIEWERS': 'ODMM_OPERATIONS_REVIEWERS'}

def collect_readonly_snapshot(*, endpoint, base_dn, version, client, max_pages=100):
    u = urlparse(endpoint)
    if u.scheme != 'ldaps' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise LDAPReadError('LDAPS_REQUIRED')
    if not isinstance(base_dn,str) or not base_dn.strip() or '\x00' in base_dn:
        raise LDAPReadError('INVALID_BASE_DN')
    if type(max_pages) is not int or not 1 <= max_pages <= 1000:
        raise LDAPReadError('INVALID_PAGE_LIMIT')
    if not hasattr(client,'search'):
        raise LDAPReadError('MISSING_READONLY_CLIENT')
    rows=[]; seen_cookies=set(); cookie=None; seen_ids=set()
    for _ in range(max_pages):
        try:
            page=client.search(base_dn, '(objectClass=person)', ATTRS, cookie)
        except Exception as exc:
            raise LDAPReadError('LDAP_READ_FAILED') from exc
        if not isinstance(page,dict) or set(page) != {'entries','next_cookie','complete'} or type(page['complete']) is not bool or not isinstance(page['entries'],list):
            raise LDAPReadError('INCOMPLETE_LDAP_PAGE')
        for entry in page['entries']:
            if not isinstance(entry,dict) or set(entry) != set(ATTRS):
                raise LDAPReadError('INVALID_LDAP_ENTRY')
            ident=entry['entryUUID']; uid=entry['uid']; uac=entry['userAccountControl']; memberships=entry['memberOf']
            if not isinstance(ident,str) or not ident.strip() or not isinstance(uid,str) or not uid.strip() or type(uac) is not int or uac < 0 or not isinstance(memberships,list) or any(not isinstance(g,str) for g in memberships):
                raise LDAPReadError('INVALID_LDAP_ENTRY')
            if ident in seen_ids: raise LDAPReadError('DUPLICATE_LDAP_ID')
            seen_ids.add(ident)
            # Unknown membership names are not translated into privileged ODMM roles.
            groups=[name for dn,name in GROUPS.items() if dn in memberships]
            rows.append({'id':ident,'enabled':not bool(uac & 2),'groups':groups})
        nxt=page['next_cookie']
        if page['complete']:
            if nxt not in (None,''): raise LDAPReadError('INCONSISTENT_COMPLETION')
            try:
                bundle=normalize_directory_export({'source':'LDAP_EXPORT','version':version,'accounts':rows})
            except Exception as exc:
                raise LDAPReadError('INVALID_DIRECTORY_SNAPSHOT') from exc
            bundle['transport']='INJECTED_CLIENT_TLS_UNVERIFIED'
            bundle['authenticated']=False
            bundle['cutover_authorized']=False
            return bundle
        if not isinstance(nxt,str) or not nxt or nxt in seen_cookies or nxt == cookie:
            raise LDAPReadError('INVALID_PAGING_COOKIE')
        seen_cookies.add(nxt); cookie=nxt
    raise LDAPReadError('LDAP_PAGE_LIMIT_EXCEEDED')
