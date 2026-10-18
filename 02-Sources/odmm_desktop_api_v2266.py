"""Read-only authenticated HTTPS status adapter. Token never persisted."""
import json
import math
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler, HTTPRedirectHandler
from odmm_desktop_jobs_v2263 import STATES

MAX_BYTES = 4 * 1024 * 1024
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('REDIRECT_REFUSED')

def validate_origin(origin):
    if not isinstance(origin, str) or origin != origin.strip():
        raise ValueError('INVALID_ORIGIN')
    try:
        p = urlsplit(origin)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:
            raise ValueError('INVALID_ORIGIN')
        if p.scheme == 'http' and p.hostname not in ('localhost','127.0.0.1','::1'):
            raise ValueError('TLS_REQUIRED')
        if not 0 < (p.port or (443 if p.scheme == 'https' else 80)) < 65536:
            raise ValueError('INVALID_PORT')
    except ValueError as exc:
        raise ValueError('INVALID_ORIGIN') from exc
    return origin.rstrip('/')

def fetch_jobs(origin, token, *, timeout=6, opener=None):
    base = validate_origin(origin)
    if not isinstance(token, str) or not (8 <= len(token) <= 8192) or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError('INVALID_TOKEN')
    if not (1 <= timeout <= 30):
        raise ValueError('INVALID_TIMEOUT')
    url = base + '/api/v1/jobs'
    request = Request(url, headers={'Authorization': 'Bearer '+token, 'Accept': 'application/json', 'Cache-Control': 'no-store'}, method='GET')
    client = opener or build_opener(HTTPSHandler(context=ssl.create_default_context()), HTTPHandler(), NoRedirect())
    with client.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError('UNEXPECTED_HTTP_STATUS')
        if 'application/json' not in response.headers.get('Content-Type','').lower():
            raise ValueError('INVALID_CONTENT_TYPE')
        raw = response.read(MAX_BYTES+1)
    if len(raw) > MAX_BYTES:
        raise ValueError('REPORT_TOO_LARGE')
    try:
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('INVALID_JSON') from exc
    if not isinstance(data, dict) or not isinstance(data.get('jobs'), list) or len(data['jobs']) > 10000:
        raise ValueError('INVALID_JOBS')
    rows=[]
    seen=set()
    for job in data['jobs']:
        if not isinstance(job, dict) or not isinstance(job.get('id'),str) or not 1 <= len(job['id']) <= 128 or any(ord(c)<32 for c in job['id']):
            raise ValueError('INVALID_JOB')
        if job['id'] in seen:
            raise ValueError('DUPLICATE_JOB_ID')
        seen.add(job['id'])
        state=job.get('status')
        if not isinstance(state,str):
            raise ValueError('INVALID_JOB_STATE')
        progress=job.get('progress_percent')
        if progress is not None and (isinstance(progress, bool) or not isinstance(progress, (int,float)) or not 0 <= progress <= 100):
            raise ValueError('INVALID_PROGRESS')
        metrics = {}
        for field in ('bytes_transferred', 'bytes_total', 'errors_count'):
            value = job.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**63-1):
                raise ValueError('INVALID_METRIC_'+field.upper())
            metrics[field] = value
        speed = job.get('throughput_bytes_per_sec')
        if speed is not None and (isinstance(speed, bool) or not isinstance(speed, (int, float)) or not math.isfinite(speed) or speed < 0 or speed > 1e15):
            raise ValueError('INVALID_THROUGHPUT')
        if metrics['bytes_total'] is not None and metrics['bytes_transferred'] is not None and metrics['bytes_transferred'] > metrics['bytes_total']:
            raise ValueError('INCONSISTENT_BYTES')
        rows.append({'id':job['id'], 'status':state.upper() if state.upper() in STATES else 'UNKNOWN', 'progress_percent':progress,
                     **metrics, 'throughput_bytes_per_sec':speed})
    return rows
