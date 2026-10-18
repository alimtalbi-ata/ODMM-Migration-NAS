"""Authenticated collector envelope verifier (HMAC-SHA256). Author: Abdelhalim Talbi.

HMAC authenticates a configured shared secret, not hardware identity. Key custody and TLS
are deployment responsibilities. Read-only; never authorizes a migration cutover.
"""
import hashlib, hmac, json, re
from datetime import datetime, timezone
from odmm_netapp_evidence_v2088 import canonical, assess_recipe

class CollectorError(ValueError): pass

def sign_envelope(payload, *, collector_id, key_id, secret, nonce, issued_at):
    if not isinstance(secret,bytes) or len(secret)<32: raise CollectorError('WEAK_KEY')
    body={'schema':'odmm.collector.envelope.v2089','collector_id':collector_id,'key_id':key_id,'nonce':nonce,'issued_at':issued_at,'payload':payload}
    body['mac']=hmac.new(secret,canonical(body),hashlib.sha256).hexdigest()
    return body

def verify_envelope(envelope, *, keyring, used_nonces, now=None, max_age_seconds=300, max_bytes=1048576):
    now=now or datetime.now(timezone.utc)
    if not isinstance(envelope,dict) or set(envelope)!={'schema','collector_id','key_id','nonce','issued_at','payload','mac'}:raise CollectorError('ENVELOPE_SCHEMA')
    if envelope['schema']!='odmm.collector.envelope.v2089':raise CollectorError('ENVELOPE_SCHEMA')
    cid,kid,nonce=envelope['collector_id'],envelope['key_id'],envelope['nonce']
    if not all(isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',v) for v in (cid,kid,nonce)):raise CollectorError('IDENTIFIER_INVALID')
    if not isinstance(envelope['mac'],str) or not re.fullmatch(r'[0-9a-f]{64}',envelope['mac']):raise CollectorError('MAC_INVALID')
    secret=keyring.get((cid,kid)) if isinstance(keyring,dict) else None
    if not isinstance(secret,bytes) or len(secret)<32:raise CollectorError('UNKNOWN_COLLECTOR_KEY')
    try:
        ts=datetime.fromisoformat(envelope['issued_at'].replace('Z','+00:00'))
        if ts.tzinfo is None or not 0<=(now-ts).total_seconds()<=max_age_seconds:raise ValueError()
    except (ValueError,TypeError,AttributeError):raise CollectorError('ENVELOPE_STALE')
    unsigned={k:v for k,v in envelope.items() if k!='mac'}
    try: blob=canonical(unsigned)
    except (TypeError,ValueError,OverflowError):raise CollectorError('ENVELOPE_PAYLOAD_INVALID')
    if len(blob)>max_bytes:raise CollectorError('ENVELOPE_OVERSIZE')
    expected=hmac.new(secret,blob,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,envelope['mac']):raise CollectorError('MAC_MISMATCH')
    replay_key=(cid,kid,nonce)
    if replay_key in used_nonces:raise CollectorError('REPLAY_DETECTED')
    # Caller must persist this set transactionally across processes to prevent replay.
    used_nonces.add(replay_key)
    return envelope['payload']

def assess_signed_recipe(source_envelope,target_envelope,identity_map,*,keyring,used_nonces,now=None):
    try:
        s=verify_envelope(source_envelope,keyring=keyring,used_nonces=used_nonces,now=now)
        t=verify_envelope(target_envelope,keyring=keyring,used_nonces=used_nonces,now=now)
        if not isinstance(s,list) or not isinstance(t,list):raise CollectorError('RECIPE_PAYLOAD_INVALID')
        trusted={source_envelope['collector_id'],target_envelope['collector_id']}
        result=assess_recipe(s,t,identity_map,trusted_collectors=trusted,now=now)
        result['schema']='odmm.netapp.signed-recipe.v2089'
        result['provenance']='HMAC-verified collector envelopes; verify channel and key custody independently'
        return result
    except CollectorError as exc:
        return {'schema':'odmm.netapp.signed-recipe.v2089','status':'BLOCKED','cutover_authorized':False,'blockers':[str(exc)],'differences':[],'pairs':[]}
