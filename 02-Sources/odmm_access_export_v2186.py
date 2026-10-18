"""Portable HMAC-authenticated audit checkpoint; key must be stored independently.
Author: Abdelhalim Talbi. No NAS/cutover certification implied.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
from odmm_access_anchor_v2185 import verify_anchored
from odmm_access_audit_v2184 import AuditError, canonical

SCHEMA='odmm.access-checkpoint.v2186'

def _key(key):
    if not isinstance(key,bytes) or len(key)<32: raise AuditError('WEAK_OR_MISSING_EXPORT_KEY')
    return key

def _mac(body,key):
    return hmac.new(_key(key),canonical(body),hashlib.sha256).hexdigest()

def create_checkpoint(audit_path,anchor_path,key,*,campaign_id):
    if not isinstance(campaign_id,str) or not campaign_id.strip(): raise AuditError('INVALID_CAMPAIGN_ID')
    state=verify_anchored(audit_path,anchor_path)
    body={'schema':SCHEMA,'campaign_id':campaign_id,'entries':state['entries'],'head':state['head'],
          'nas_qualified':False,'cutover_authorized':False}
    return {'body':body,'hmac_sha256':_mac(body,key)}

def verify_checkpoint(checkpoint,key,*,audit_path=None,anchor_path=None):
    if not isinstance(checkpoint,dict) or set(checkpoint)!={'body','hmac_sha256'}: raise AuditError('INVALID_CHECKPOINT')
    body=checkpoint['body']
    if not isinstance(body,dict) or set(body)!={'schema','campaign_id','entries','head','nas_qualified','cutover_authorized'}:
        raise AuditError('INVALID_CHECKPOINT_BODY')
    if body['schema']!=SCHEMA or body['nas_qualified'] is not False or body['cutover_authorized'] is not False:
        raise AuditError('UNTRUSTED_CHECKPOINT')
    if not isinstance(body['entries'],int) or isinstance(body['entries'],bool) or body['entries']<0 or not isinstance(body['head'],str) or len(body['head'])!=64:
        raise AuditError('INVALID_CHECKPOINT_BODY')
    if not isinstance(checkpoint['hmac_sha256'],str) or not hmac.compare_digest(_mac(body,key),checkpoint['hmac_sha256']):
        raise AuditError('CHECKPOINT_AUTHENTICATION_FAILED')
    if (audit_path is None)!=(anchor_path is None): raise AuditError('INCOMPLETE_AUDIT_PATHS')
    if audit_path is not None:
        observed=verify_anchored(audit_path,anchor_path)
        if (observed['entries'],observed['head'])!=(body['entries'],body['head']):
            raise AuditError('CHECKPOINT_HEAD_MISMATCH')
    return {'authenticated':True,'entries':body['entries'],'head':body['head'],'nas_qualified':False,'cutover_authorized':False}

def write_checkpoint(path,checkpoint):
    """Exclusive create; no overwrite or symlink following. Store outside audit host."""
    target=Path(path)
    fd=os.open(str(target),os.O_WRONLY|os.O_CREAT|os.O_EXCL| getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(canonical(checkpoint)+b'\n')
            f.flush();os.fsync(f.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return str(target)

def read_checkpoint(path,max_bytes=8192):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>max_bytes: raise AuditError('UNSAFE_CHECKPOINT_FILE')
    return json.loads(p.read_bytes())
