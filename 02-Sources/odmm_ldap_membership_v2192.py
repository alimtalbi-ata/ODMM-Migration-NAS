"""Strict paged LDAP membership evidence collector (injected read-only client).
Author: Abdelhalim Talbi. No live authentication or NAS certification implied.
"""
import hashlib
import json
import time
from urllib.parse import urlparse

class MembershipCollectionError(ValueError):
    pass

def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()

def collect_memberships(*, endpoint, base_dn, client, max_pages=100, max_age_seconds=300,
                        observed_at=None, now=None):
    parsed = urlparse(endpoint)
    if parsed.scheme != 'ldaps' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise MembershipCollectionError('LDAPS_REQUIRED')
    if not isinstance(base_dn, str) or not base_dn.strip() or type(max_pages) is not int or not 1 <= max_pages <= 10000:
        raise MembershipCollectionError('INVALID_CONFIGURATION')
    if type(max_age_seconds) not in (int, float) or not 0 < max_age_seconds <= 86400:
        raise MembershipCollectionError('INVALID_MAX_AGE')
    now = time.time() if now is None else now
    observed_at = now if observed_at is None else observed_at
    if type(now) not in (int, float) or type(observed_at) not in (int, float) or not 0 <= now-observed_at <= max_age_seconds:
        raise MembershipCollectionError('STALE_OR_FUTURE_OBSERVATION')
    cookie = None
    seen_cookies = set()
    accounts = {}
    groups = {}
    for _ in range(max_pages):
        try:
            page = client.search(base=base_dn, filter='(|(objectClass=person)(objectClass=group))',
                                 attributes=('entryUUID', 'uid', 'distinguishedName', 'objectClass', 'memberOf', 'member'), cookie=cookie)
        except Exception as exc:
            raise MembershipCollectionError('DIRECTORY_READ_FAILED') from exc
        if not isinstance(page, dict) or not isinstance(page.get('entries'), list) or page.get('complete') is not (not bool(page.get('next_cookie'))):
            raise MembershipCollectionError('INCOMPLETE_PAGE')
        for item in page['entries']:
            if not isinstance(item, dict):
                raise MembershipCollectionError('INVALID_ENTRY')
            dn = item.get('distinguishedName')
            classes = item.get('objectClass')
            if not isinstance(dn, str) or not dn.strip() or not isinstance(classes, list):
                raise MembershipCollectionError('INVALID_DN_OR_CLASS')
            key = dn.casefold()
            if key in accounts or key in groups:
                raise MembershipCollectionError('DUPLICATE_DN')
            if 'group' in [str(x).lower() for x in classes]:
                members = item.get('member', [])
                if not isinstance(members, list) or any(not isinstance(x, str) or not x for x in members):
                    raise MembershipCollectionError('INVALID_GROUP_MEMBERS')
                groups[key] = sorted(x.casefold() for x in members)
            else:
                uid = item.get('entryUUID')
                memberships = item.get('memberOf', [])
                if not isinstance(uid, str) or not uid or not isinstance(memberships, list) or any(not isinstance(x, str) or not x for x in memberships):
                    raise MembershipCollectionError('INVALID_ACCOUNT')
                if any(a['id'] == uid for a in accounts.values()):
                    raise MembershipCollectionError('DUPLICATE_ID')
                accounts[key] = {'id': uid, 'direct_groups': sorted(x.casefold() for x in memberships)}
        nxt = page.get('next_cookie')
        if not nxt:
            break
        if not isinstance(nxt, (str, bytes)) or nxt in seen_cookies:
            raise MembershipCollectionError('PAGINATION_LOOP')
        seen_cookies.add(nxt)
        cookie = nxt
    else:
        raise MembershipCollectionError('PAGE_LIMIT_EXCEEDED')
    for dn, account in accounts.items():
        for group in account['direct_groups']:
            if group not in groups or dn not in groups[group]:
                raise MembershipCollectionError('MEMBERSHIP_NOT_RECIPROCAL')
    for group, members in groups.items():
        if len(set(members)) != len(members) or any(m not in accounts and m not in groups for m in members):
            raise MembershipCollectionError('UNKNOWN_OR_DUPLICATE_MEMBER')
    def visit(group, trail):
        if group in trail:
            raise MembershipCollectionError('GROUP_CYCLE')
        result = set()
        for member in groups[group]:
            if member in accounts:
                result.add(accounts[member]['id'])
            else:
                result.update(visit(member, trail | {group}))
        return result
    resolved = {group: sorted(visit(group, set())) for group in sorted(groups)}
    report = {'schema': 'odmm.ldap-membership.v2192', 'endpoint_host': parsed.hostname,
              'observed_at': observed_at, 'max_age_seconds': max_age_seconds,
              'accounts': dict(sorted(accounts.items())), 'groups': dict(sorted(groups.items())),
              'resolved_members': resolved, 'pages': len(seen_cookies)+1,
              'directory_authenticated': False, 'nas_access_verified': False, 'cutover_authorized': False,
              'limitations': ['INJECTED_CLIENT_NOT_AUTHENTICATION_PROOF', 'NO_NAS_EFFECTIVE_ACCESS_TEST']}
    return {'report': report, 'sha256': _hash(report)}
