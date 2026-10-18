"""Fail-closed browser write guard and externally stored review head anchor.
Author: Abdelhalim Talbi. An anchor on the same host is not independent custody.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import HTTPException
from qualification_decisions_v2215 import _connect, _read_verified


def browser_write_guard(request, *, trusted_origins, require_bearer=True):
    """Origin check plus non-cookie bearer requirement to mitigate CSRF.
    Authentication of bearer credentials remains responsibility of caller's identity provider.
    """
    if not trusted_origins or any(not isinstance(x,str) or not x.startswith('https://') or urlsplit(x).path not in ('','/') for x in trusted_origins):
        raise ValueError('INVALID_TRUSTED_ORIGINS')
    origin = request.headers.get('origin', '')
    if origin not in trusted_origins:
        raise HTTPException(403, 'UNTRUSTED_ORIGIN')
    if require_bearer and (not request.headers.get('authorization', '').startswith('Bearer ') or not request.headers.get('authorization', '')[7:].strip()):
        raise HTTPException(403, 'BEARER_REQUIRED')
    if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
        raise HTTPException(415, 'JSON_REQUIRED')


def review_head(db_path, secret):
    con = _connect(db_path)
    try:
        events = _read_verified(con, secret)
        return {'schema':'odmm.review.anchor.v2217', 'count':len(events),
                'head_mac':events[-1]['mac'] if events else 'GENESIS'}
    finally:
        con.close()


def write_anchor(db_path, anchor_path, secret):
    """Write a signed head to an operator-managed independent location.
    Callers must copy/store this anchor outside the database trust boundary.
    """
    if not isinstance(secret,bytes) or len(secret)<32:
        raise ValueError('INVALID_KEY')
    head=review_head(db_path,secret)
    mac=hmac.new(secret,b'ODMM-ANCHOR-V2217\0'+json.dumps(head,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
    dest=Path(anchor_path)
    if not dest.parent.is_dir(): raise ValueError('ANCHOR_DIRECTORY_MISSING')
    fd,name=tempfile.mkstemp(prefix='.odmm-anchor-',dir=str(dest.parent))
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump({'head':head,'hmac_sha256':mac},f,sort_keys=True)
            f.flush();os.fsync(f.fileno())
        os.replace(name,dest)
    finally:
        if os.path.exists(name): os.unlink(name)
    return head


def verify_anchor(db_path, anchor_path, secret):
    data=json.loads(Path(anchor_path).read_text(encoding='utf-8'))
    head=data['head']
    expected=hmac.new(secret,b'ODMM-ANCHOR-V2217\0'+json.dumps(head,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,data['hmac_sha256']):
        raise ValueError('ANCHOR_AUTHENTICATION_FAILURE')
    current=review_head(db_path,secret)
    if current!=head: raise ValueError('REVIEW_HEAD_CHANGED_OR_ROLLED_BACK')
    return True
