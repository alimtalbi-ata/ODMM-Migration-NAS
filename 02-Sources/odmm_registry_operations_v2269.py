"""Read-only per-job operation inspection using the deployed ODMM API contract."""
import json, ssl
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from odmm_desktop_api_v2266 import validate_origin, NoRedirect, MAX_BYTES

STATES = frozenset({'PENDING', 'RUNNING', 'DONE', 'FAILED'})

def normalize_operations(data, job_id):
    if not isinstance(data, dict) or data.get('schema') != 'odmm.operations.v1' or data.get('read_only') is not True or data.get('job_id') != job_id:
        raise ValueError('INVALID_OPERATIONS_CONTRACT')
    items = data.get('items')
    if not isinstance(items, list) or len(items) > 200:
        raise ValueError('INVALID_OPERATIONS_ITEMS')
    result, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or item.get('job_id') != job_id:
            raise ValueError('INVALID_OPERATION')
        oid, state = item.get('id'), item.get('state')
        if not isinstance(oid, str) or not 1 <= len(oid) <= 128 or any(ord(c) < 32 for c in oid) or oid in seen or state not in STATES:
            raise ValueError('INVALID_OPERATION_ID_OR_STATE')
        owner = item.get('owner')
        if owner is not None and (not isinstance(owner,str) or len(owner)>256 or any(ord(c)<32 for c in owner)):
            raise ValueError('INVALID_OWNER')
        epoch = item.get('epoch')
        if epoch is not None and (isinstance(epoch,bool) or not isinstance(epoch,int) or epoch < 0):
            raise ValueError('INVALID_EPOCH')
        lease = item.get('lease_until')
        if lease is not None and (not isinstance(lease,(int,float,str)) or isinstance(lease,bool) or len(str(lease)) > 80):
            raise ValueError('INVALID_LEASE')
        seen.add(oid)
        result.append({'id':oid,'state':state,'owner':owner,'epoch':epoch,'lease_until':lease})
    return result

def fetch_operations(origin, token, job_id, *, timeout=6, opener=None):
    base = validate_origin(origin)
    if not isinstance(job_id,str) or not 1 <= len(job_id) <= 128 or any(ord(c)<32 for c in job_id):
        raise ValueError('INVALID_JOB_ID')
    if not isinstance(token,str) or not 8 <= len(token) <= 8192 or any(ord(c)<33 or ord(c)>126 for c in token):
        raise ValueError('INVALID_TOKEN')
    if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not 1 <= timeout <= 30:
        raise ValueError('INVALID_TIMEOUT')
    url = base + '/api/v1/operations/jobs/' + quote(job_id,safe='') + '/operations?limit=200'
    request = Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/json','Cache-Control':'no-store'},method='GET')
    client = opener or build_opener(HTTPSHandler(context=ssl.create_default_context()),HTTPHandler(),NoRedirect())
    with client.open(request,timeout=timeout) as response:
        if response.status != 200 or 'application/json' not in response.headers.get('Content-Type','').lower():
            raise ValueError('INVALID_HTTP_RESPONSE')
        raw=response.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES: raise ValueError('REPORT_TOO_LARGE')
    try: data=json.loads(raw.decode('utf-8'))
    except (ValueError,UnicodeError) as exc: raise ValueError('INVALID_JSON') from exc
    return normalize_operations(data,job_id)
