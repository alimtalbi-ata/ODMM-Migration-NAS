"""Strict read-only REST transport boundary for ODMM vendor inventory.

Author: Abdelhalim Talbi. API routes and response schemas MUST be explicitly
qualified per firmware; this module does not claim device compatibility.
"""
from dataclasses import dataclass
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit, urlencode, quote
import ipaddress
import json
import re
from odmm_nas_vendor_collector_v2131 import SUPPORTED, collect_vendor_inventory

@dataclass(frozen=True)
class RestProfile:
    vendor: str
    api_version: str
    route: str
    records_key: str
    next_key: str
    firmware_pattern: str
    qualified: bool = False


def _safe_base(base):
    if not isinstance(base, str):
        raise ValueError('HTTPS_BASE_REQUIRED')
    u = urlsplit(base)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/') or u.port is None:
        raise ValueError('HTTPS_PINNED_HOST_PORT_REQUIRED')
    # The transport must pin DNS resolution and TLS certificate verification.
    # Reject IP literals and localhost to reduce accidental internal SSRF.
    try:
        ipaddress.ip_address(u.hostname)
    except ValueError:
        pass
    else:
        raise ValueError('IP_LITERAL_NOT_ALLOWED')
    if u.hostname.lower() == 'localhost' or not re.fullmatch(r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+', u.hostname):
        raise ValueError('HOSTNAME_INVALID')
    return urlunsplit(('https', u.netloc, '', '', ''))


def make_rest_page_fetcher(*, base_url, profile, manifest, token, transport, timeout=10, max_response_bytes=2_000_000):
    """Transport signature: transport(url, headers, timeout, max_response_bytes) -> bytes.

    Transport is injected for deterministic testing. Production transport MUST
    enforce GET-only, verified TLS, pinned DNS, no redirects, byte/time limits.
    A Python callback alone cannot prove those properties.
    """
    base = _safe_base(base_url)
    if not isinstance(profile, RestProfile) or profile.vendor not in SUPPORTED:
        raise ValueError('PROFILE_INVALID')
    if not isinstance(manifest, Mapping) or manifest.get('vendor') != profile.vendor:
        raise ValueError('VENDOR_MISMATCH')
    if profile.qualified is not True:
        raise ValueError('UNQUALIFIED_VENDOR_API')
    if not isinstance(profile.api_version, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', profile.api_version):
        raise ValueError('API_VERSION_INVALID')
    if not isinstance(profile.route, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,200}', profile.route) or '..' in profile.route or '//' in profile.route:
        raise ValueError('ROUTE_INVALID')
    if any(not isinstance(k,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',k) for k in (profile.records_key, profile.next_key)):
        raise ValueError('RESPONSE_KEYS_INVALID')
    if not isinstance(profile.firmware_pattern,str) or not profile.firmware_pattern or len(profile.firmware_pattern)>128:
        raise ValueError('FIRMWARE_RULE_INVALID')
    # Literal full-match, not arbitrary regex supplied by an external actor.
    if manifest.get('firmware') != profile.firmware_pattern:
        raise ValueError('FIRMWARE_NOT_QUALIFIED')
    if not isinstance(token,str) or not token or len(token)>4096 or any(ord(c)<33 or ord(c)>126 for c in token):
        raise ValueError('TOKEN_INVALID')
    if not callable(transport) or type(timeout) not in (int,float) or not 0<timeout<=30 or type(max_response_bytes) is not int or not 1024<=max_response_bytes<=8_000_000:
        raise ValueError('TRANSPORT_CONFIG_INVALID')
    def fetch(cursor):
        if cursor is not None and (not isinstance(cursor,str) or not cursor or len(cursor)>1024 or any(ord(c)<33 or ord(c)>126 for c in cursor)):
            raise ValueError('CURSOR_INVALID')
        suffix = '?' + urlencode({'cursor':cursor},quote_via=quote) if cursor is not None else ''
        url = base + profile.route + suffix
        try:
            raw = transport(url, {'Authorization':'Bearer '+token, 'Accept':'application/json'}, timeout, max_response_bytes)
        except Exception as exc:
            raise ValueError('REST_TRANSPORT_FAILED') from exc
        if not isinstance(raw,bytes) or len(raw)>max_response_bytes:
            raise ValueError('RESPONSE_SIZE_INVALID')
        try:
            data=json.loads(raw)
        except (ValueError,UnicodeError) as exc:
            raise ValueError('JSON_RESPONSE_INVALID') from exc
        if not isinstance(data,dict) or type(data.get(profile.records_key)) is not list:
            raise ValueError('REST_SCHEMA_INVALID')
        if profile.next_key not in data:
            raise ValueError('PAGINATION_COMPLETENESS_UNPROVEN')
        return {'records':data[profile.records_key], 'next_token':data[profile.next_key]}
    return fetch


def collect_rest_inventory(*, base_url, profile, manifest, token, transport, **kwargs):
    fetch = make_rest_page_fetcher(base_url=base_url, profile=profile, manifest=manifest, token=token, transport=transport)
    return collect_vendor_inventory(vendor=profile.vendor,manifest=manifest,fetch_page=fetch,**kwargs)
