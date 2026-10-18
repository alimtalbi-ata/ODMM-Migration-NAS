"""V188.7: bounded, read-only local technical observations; no disruption or cutover.

Observations are evidence of probe output, NOT proof of remote host independence.
"""
import hashlib
import json
import os
import socket
import sqlite3
import time
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_observation_hardened import observe_file

SAFE = ('cutover_authorized', 'recovery_authorized', 'publication_authorized')

def collect_local(*, host, run_id, incident_id, scenario, probe, timeout=2.0):
    """Collect one bounded local observation, with no mutation of remote state.

    probe: ('tcp', hostname, port) or ('file_sha256', absolute_path).
    TCP connection alone is not a successful mTLS handshake.
    """
    if host not in ('source', 'witness') or not all(isinstance(v,str) and v.strip() for v in (run_id,incident_id,scenario)):
        raise IdentityPinError('OBSERVATION_CONTEXT_INVALID')
    if not isinstance(timeout,(int,float)) or isinstance(timeout,bool) or not 0 < timeout <= 10:
        raise IdentityPinError('OBSERVATION_TIMEOUT_INVALID')
    if not isinstance(probe,(tuple,list)) or len(probe) < 2:
        raise IdentityPinError('OBSERVATION_PROBE_INVALID')
    kind=probe[0]
    if kind=='tcp' and len(probe)==3:
        hostname,port=probe[1:]
        if not isinstance(hostname,str) or not hostname.strip() or not isinstance(port,int) or isinstance(port,bool) or not 1<=port<=65535:
            raise IdentityPinError('OBSERVATION_TARGET_INVALID')
        try:
            with socket.create_connection((hostname,port),timeout=timeout):
                result='CONNECTED'
        except (OSError,TimeoutError):
            result='UNAVAILABLE'
        target=f'{hostname}:{port}'
    elif kind=='file_sha256' and len(probe)==2:
        path=Path(probe[1])
        # V188.9: enforce bounded, descriptor-based, no-follow file hashing.
        # The former is_symlink/stat/read_bytes sequence was vulnerable to
        # path replacement and unbounded reads between check and use.
        result=observe_file(path)['sha256']
        target=str(path)
    else:
        raise IdentityPinError('OBSERVATION_PROBE_INVALID')
    return {'schema':1,'host':host,'run_id':run_id,'incident_id':incident_id,'scenario':scenario,
            'probe_type':kind,'target':target,'result':result,'timestamp_ns':time.time_ns(),
            'collector_pid':os.getpid(),'technical_execution_independently_proven':False,
            'manual_review_required':True,**{k:False for k in SAFE}}

class ObservationRegistry:
    """Atomic idempotency gate across processes. One run/host/probe, fail-closed."""
    def __init__(self,path): self.path=Path(path)
    def register(self,observation):
        if not isinstance(observation,dict) or set(observation)!={'schema','host','run_id','incident_id','scenario','probe_type','target','result','timestamp_ns','collector_pid','technical_execution_independently_proven','manual_review_required',*SAFE}:
            raise IdentityPinError('OBSERVATION_SCHEMA_INVALID')
        if observation['schema']!=1 or observation['host'] not in ('source','witness') or observation['probe_type'] not in ('tcp','file_sha256') or observation['technical_execution_independently_proven'] is not False or observation['manual_review_required'] is not True or any(observation[k] is not False for k in SAFE):
            raise IdentityPinError('OBSERVATION_UNSAFE')
        if not all(isinstance(observation[k],str) and observation[k] for k in ('run_id','incident_id','scenario','target','result')):
            raise IdentityPinError('OBSERVATION_FIELDS_INVALID')
        if not isinstance(observation['timestamp_ns'],int) or not isinstance(observation['collector_pid'],int):
            raise IdentityPinError('OBSERVATION_FIELDS_INVALID')
        payload=json.dumps(observation,sort_keys=True,separators=(',',':')).encode()
        digest=hashlib.sha256(payload).hexdigest()
        with sqlite3.connect(self.path,timeout=5) as db:
            db.execute('CREATE TABLE IF NOT EXISTS observations (run_id TEXT NOT NULL, host TEXT NOT NULL, probe_type TEXT NOT NULL, target TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(run_id,host,probe_type,target))')
            try:
                db.execute('BEGIN IMMEDIATE')
                db.execute('INSERT INTO observations VALUES (?,?,?,?,?)',(observation['run_id'],observation['host'],observation['probe_type'],observation['target'],digest))
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise IdentityPinError('OBSERVATION_REPLAY_DETECTED') from exc
        return {'status':'OBSERVATION_RECORDED_REVIEW_REQUIRED','digest':digest,'manual_review_required':True,**{k:False for k in SAFE}}
