"""Read-only adapter for the actual ODMM OperationsView jobs endpoint.

No migration control operations are exposed. Registry states are not transfer metrics.
"""
import json
import ssl
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from odmm_desktop_api_v2266 import validate_origin, NoRedirect, MAX_BYTES

REGISTRY_STATES = {'PENDING', 'RUNNING', 'DONE', 'FAILED'}

def normalize_registry_jobs(data):
    if not isinstance(data, dict) or data.get('schema') != 'odmm.jobs.v1' or data.get('read_only') is not True:
        raise ValueError('INVALID_REGISTRY_CONTRACT')
    items = data.get('items')
    if not isinstance(items, list) or len(items) > 200:
        raise ValueError('INVALID_REGISTRY_ITEMS')
    result, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('INVALID_REGISTRY_JOB')
        jid, state = item.get('id'), item.get('state')
        if not isinstance(jid, str) or not 1 <= len(jid) <= 128 or any(ord(c) < 32 for c in jid) or jid in seen:
            raise ValueError('INVALID_REGISTRY_ID')
        if not isinstance(state, str) or state not in REGISTRY_STATES:
            raise ValueError('INVALID_REGISTRY_STATE')
        seen.add(jid)
        result.append({'id': jid, 'status': 'COMPLETED' if state == 'DONE' else state,
                       'progress_percent': None, 'bytes_transferred': None, 'bytes_total': None,
                       'throughput_bytes_per_sec': None, 'errors_count': None})
    return result

def _unique_json_object(pairs):
    """Reject ambiguous duplicate JSON members at every nesting level."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('INVALID_JSON')
        result[key] = value
    return result


def fetch_registry_jobs(origin, token, *, timeout=6, opener=None):
    base = validate_origin(origin)
    if not isinstance(token, str) or not 8 <= len(token) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError('INVALID_TOKEN')
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 30:
        raise ValueError('INVALID_TIMEOUT')
    request = Request(base + '/api/v1/operations/jobs?limit=200',
                      headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
                               'Cache-Control': 'no-store'}, method='GET')
    client = opener or build_opener(HTTPSHandler(context=ssl.create_default_context()), HTTPHandler(), NoRedirect())
    with client.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError('UNEXPECTED_HTTP_STATUS')
        if 'application/json' not in response.headers.get('Content-Type', '').lower():
            raise ValueError('INVALID_CONTENT_TYPE')
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('REPORT_TOO_LARGE')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_json_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('INVALID_JSON')))
    except (UnicodeError, ValueError) as exc:
        raise ValueError('INVALID_JSON') from exc
    return normalize_registry_jobs(data)
