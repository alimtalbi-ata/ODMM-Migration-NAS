"""Bounded read-only NAS API evidence collector; NOT vendor-certified.
Author: Abdelhalim Talbi. No network I/O; injected transport owns TLS/DNS/auth.
"""
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, quote

VENDORS = frozenset(('netapp_ontap', 'pure_flashblade', 'dell_onefs'))
SAFE = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')

@dataclass(frozen=True)
class Profile:
    vendor: str
    firmware: str
    route: str
    records_key: str
    next_key: str
    evidence_id: str
    schema_reviewed: bool = False


def _base_url(value):
    if type(value) is not str:
        raise ValueError('INVALID_URL')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if (parsed.scheme != 'https' or not host or not port or parsed.username is not None
                or parsed.password is not None or parsed.path not in ('', '/') or parsed.query
                or parsed.fragment or not host.isascii() or host.endswith('.') or host.lower() == 'localhost'):
            raise ValueError('INVALID_URL')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', host):
                raise ValueError('INVALID_URL')
        else:
            raise ValueError('IP_LITERAL_NOT_ALLOWED')
        return f'https://{host.lower()}:{port}'
    except (ValueError, TypeError) as exc:
        raise ValueError('INVALID_URL') from exc


def collect_pages(*, base_url, profile, transport, authorization, max_pages=32,
                  max_bytes=1_000_000, max_records=100_000):
    """transport(url, *, headers, max_bytes, redirects, tls_verify) -> bytes.

    Transport MUST pin DNS, validate certificates and use GET only. Credentials
    never enter returned evidence or errors. Profile review is caller asserted.
    """
    base = _base_url(base_url)
    if type(profile) is not Profile or profile.vendor not in VENDORS:
        raise ValueError('INVALID_PROFILE')
    if (not SAFE.fullmatch(profile.firmware) or not SAFE.fullmatch(profile.evidence_id)
            or not SAFE.fullmatch(profile.records_key) or not SAFE.fullmatch(profile.next_key)
            or type(profile.schema_reviewed) is not bool):
        raise ValueError('INVALID_PROFILE')
    if (type(profile.route) is not str or not re.fullmatch(r'/[A-Za-z0-9/_-]{1,256}', profile.route)
            or '//' in profile.route or '/..' in profile.route):
        raise ValueError('INVALID_ROUTE')
    if not callable(transport) or type(authorization) is not str or not authorization.startswith('Bearer '):
        raise ValueError('TRANSPORT_OR_AUTH_REQUIRED')
    if (type(max_pages) is not int or not 1 <= max_pages <= 1000
            or type(max_bytes) is not int or not 1024 <= max_bytes <= 2_000_000
            or type(max_records) is not int or not 1 <= max_records <= 100_000):
        raise ValueError('INVALID_LIMIT')
    seen = set()
    cursor = None
    records = []
    page_hashes = []
    for _ in range(max_pages):
        url = base + profile.route + (('?cursor=' + quote(cursor, safe='')) if cursor else '')
        try:
            raw = transport(url, headers={'Authorization': authorization, 'Accept': 'application/json'},
                            max_bytes=max_bytes, redirects=False, tls_verify=True)
            if type(raw) is not bytes or len(raw) > max_bytes:
                raise ValueError('INVALID_BODY')
            obj = json.loads(raw)
            if type(obj) is not dict or set((profile.records_key, profile.next_key)) - set(obj):
                raise ValueError('INVALID_SCHEMA')
            rows, nxt = obj[profile.records_key], obj[profile.next_key]
            if type(rows) is not list or not all(type(r) is dict for r in rows):
                raise ValueError('INVALID_RECORDS')
            if nxt is not None and (type(nxt) is not str or not 1 <= len(nxt) <= 512
                                    or any(ord(c) < 32 for c in nxt)):
                raise ValueError('INVALID_CURSOR')
        except Exception as exc:
            raise ValueError('NAS_COLLECTION_FAILED') from None
        records.extend(rows)
        if len(records) > max_records:
            raise ValueError('RECORD_LIMIT_EXCEEDED')
        page_hashes.append(hashlib.sha256(raw).hexdigest())
        if nxt is None:
            digest = hashlib.sha256(json.dumps({'vendor': profile.vendor, 'firmware': profile.firmware,
                'evidence_id': profile.evidence_id, 'page_hashes': page_hashes},
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            return {'vendor': profile.vendor, 'firmware': profile.firmware, 'evidence_id': profile.evidence_id,
                'page_count': len(page_hashes), 'record_count': len(records), 'records': records,
                'page_hashes': page_hashes, 'digest': digest, 'pagination_complete': True,
                'schema_reviewed_by_caller': profile.schema_reviewed,
                'blockers': ['VENDOR_FIRMWARE_NOT_INDEPENDENTLY_CERTIFIED',
                             'TLS_DNS_TRANSPORT_NOT_INDEPENDENTLY_ATTESTED',
                             'ACL_AND_EFFECTIVE_ACCESS_NOT_VERIFIED', 'CUTOVER_NOT_AUTHORIZED'],
                'engine': 'ODMM_NATIVE', 'certified': False, 'cutover_authorized': False}
        if nxt in seen:
            raise ValueError('CURSOR_CYCLE')
        seen.add(nxt)
        cursor = nxt
    raise ValueError('PAGINATION_LIMIT_EXCEEDED')
