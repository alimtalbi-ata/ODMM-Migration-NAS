"""Read-only, injected-page NAS inventory collector; author Abdelhalim Talbi.

No vendor REST endpoints are assumed. A qualified connector must supply a
firmware-specific manifest and a page fetcher. This is not live appliance testing.
"""
from dataclasses import dataclass
from collections.abc import Mapping
from datetime import datetime, timezone
from odmm_nas_firmware_evidence_v2130 import inspect_endpoint

SUPPORTED = frozenset(('netapp_ontap','pure_flashblade','dell_onefs'))

@dataclass(frozen=True)
class CollectionResult:
    endpoint: object
    page_count: int
    records: tuple
    blockers: tuple[str, ...]
    engine: str = 'ODMM_NATIVE'
    cutover_authorized: bool = False
    certified: bool = False

def collect_vendor_inventory(*, vendor, manifest, fetch_page, max_pages=100):
    """fetch_page(token) -> {records:list[dict], next_token:str|None}.

    Every page is fetched via a caller-provided read-only transport; caller must
    enforce transport GET-only, TLS and authorization. A signed vendor adapter
    is still required before trusting the evidence as device-originated.
    """
    if vendor not in SUPPORTED:
        raise ValueError('VENDOR_ADAPTER_NOT_SUPPORTED')
    if not isinstance(manifest, Mapping) or manifest.get('vendor') != vendor:
        raise ValueError('MANIFEST_VENDOR_MISMATCH')
    if not callable(fetch_page) or type(max_pages) is not int or not 1 <= max_pages <= 1000:
        raise ValueError('COLLECTOR_CONFIG_INVALID')
    if manifest.get('read_only') is not True:
        raise ValueError('READ_ONLY_MANIFEST_REQUIRED')
    if manifest.get('collection_method') != 'API_READONLY':
        raise ValueError('API_READONLY_REQUIRED')
    token=None; seen=set(); records=[]; pages=0
    while True:
        if pages >= max_pages:
            raise ValueError('PAGINATION_LIMIT_EXCEEDED')
        try:
            page=fetch_page(token)
        except Exception as exc:
            raise ValueError('COLLECTION_PAGE_FAILED') from exc
        if not isinstance(page, Mapping) or not isinstance(page.get('records'), list):
            raise ValueError('PAGE_FORMAT_INVALID')
        if any(not isinstance(row,Mapping) for row in page['records']):
            raise ValueError('RECORD_FORMAT_INVALID')
        if len(records)+len(page['records']) > 100000:
            raise ValueError('RECORD_LIMIT_EXCEEDED')
        records.extend(dict(row) for row in page['records']); pages+=1
        nxt=page.get('next_token')
        if nxt is None:
            break
        if not isinstance(nxt,str) or not nxt or len(nxt)>1024 or any(ord(c)<32 for c in nxt) or nxt in seen:
            raise ValueError('PAGINATION_TOKEN_INVALID_OR_CYCLE')
        seen.add(nxt); token=nxt
    raw=dict(manifest)
    # Only pagination is proven by the collection loop. Never infer ACL completeness,
    # firmware compatibility, or independent vendor certification from page count.
    raw['pagination_complete']=True
    endpoint=inspect_endpoint(raw,expected_vendor=vendor)
    blockers=['NOT_INDEPENDENTLY_CERTIFIED','ACL_AND_EFFECTIVE_ACCESS_NOT_PROVEN',
              'NO_DISTRIBUTED_FENCING_OR_ROLLBACK_PROOF']
    blockers.extend(endpoint.warnings)
    return CollectionResult(endpoint,pages,tuple(records),tuple(sorted(set(blockers))))
