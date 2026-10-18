"""V192.0 authenticated benchmark history; independent of untrusted SHA-only history.

HMAC key material is supplied by the caller and never persisted in the journal.
Key rotation records are authenticated by BOTH the outgoing and incoming key.
"""
import hashlib
import hmac
import os
import fcntl
import json
from native_benchmark_integrity import _canonical, _read_locked, _open, GENESIS
from native_benchmark_history import _safe_report

MAX_RECORDS=100000

def _key(keys, kid):
    if not isinstance(kid,str) or not kid or kid not in keys: raise ValueError('UNKNOWN_KEY')
    key=keys[kid]
    if not isinstance(key,bytes) or len(key)<32: raise ValueError('INVALID_KEY')
    return key

def _mac(key, base):
    return hmac.new(key,_canonical(base),hashlib.sha256).hexdigest()

def _check(raw, keys, *, trusted_head=None):
    previous=GENESIS; current=None; result=[]
    for seq,line in enumerate(raw.splitlines(),1):
        if seq>MAX_RECORDS: raise ValueError('HISTORY_TOO_LARGE')
        try:
            item=json.loads(line)
            kind=item['kind']
            if kind=='start':
                if seq!=1 or current is not None or set(item)!={'seq','previous','kind','key_id','mac'}:raise ValueError('BAD_START')
                current=item['key_id']; base={k:v for k,v in item.items() if k!='mac'}
                if not hmac.compare_digest(_mac(_key(keys,current),base),item['mac']):raise ValueError('BAD_MAC')
            elif kind=='report':
                if current is None or set(item)!={'seq','previous','kind','key_id','report','mac'} or item['key_id']!=current:raise ValueError('BAD_REPORT')
                if _safe_report(item['report'])!=item['report']:raise ValueError('BAD_REPORT')
                base={k:v for k,v in item.items() if k!='mac'}
                if not hmac.compare_digest(_mac(_key(keys,current),base),item['mac']):raise ValueError('BAD_MAC')
            elif kind=='rotate':
                if current is None or set(item)!={'seq','previous','kind','from_key','to_key','old_mac','new_mac'} or item['from_key']!=current or item['to_key']==current:raise ValueError('BAD_ROTATION')
                base={k:v for k,v in item.items() if k not in ('old_mac','new_mac')}
                if not hmac.compare_digest(_mac(_key(keys,current),base),item['old_mac']):raise ValueError('BAD_OLD_MAC')
                if not hmac.compare_digest(_mac(_key(keys,item['to_key']),base),item['new_mac']):raise ValueError('BAD_NEW_MAC')
                current=item['to_key']
            else:raise ValueError('BAD_KIND')
            if type(item['seq']) is not int or item['seq']!=seq or item['previous']!=previous:raise ValueError('BROKEN_CHAIN')
            previous=hashlib.sha256(_canonical(item)).hexdigest()
            result.append(item)
        except (ValueError,KeyError,TypeError,UnicodeError,AttributeError) as exc:
            raise ValueError('AUTHENTICATED_HISTORY_INVALID') from exc
    if trusted_head is not None and not hmac.compare_digest(previous,trusted_head):raise ValueError('TRUSTED_HEAD_MISMATCH')
    return result,current,previous

def _append_batch(fd, items):
    """Append one logical transaction in one prepared byte stream.

    A filesystem write is not a durable atomic transaction: any partial write
    is detected and rejected by the strict newline/chain verifier on recovery.
    """
    data=b''.join(_canonical(item)+b'\n' for item in items)
    os.lseek(fd,0,os.SEEK_END)
    while data:
        n=os.write(fd,data)
        if n<=0:raise OSError('SHORT_WRITE')
        data=data[n:]
    os.fsync(fd)
    item=items[-1]
    return {'seq':item['seq'],'head_sha256':hashlib.sha256(_canonical(item)).hexdigest(),'cutover_authorized':False}

def _append(fd,item):
    return _append_batch(fd,[item])

def append_authenticated(path,report,*,keys,key_id=None,trusted_head=None):
    safe=_safe_report(report)
    fd=_open(path)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        records,current,previous=_check(_read_locked(fd),keys,trusted_head=trusted_head)
        if not records:
            if not key_id:raise ValueError('INITIAL_KEY_REQUIRED')
            _key(keys,key_id)
            base={'seq':1,'previous':GENESIS,'kind':'start','key_id':key_id}
            start={**base,'mac':_mac(keys[key_id],base)}
            previous=hashlib.sha256(_canonical(start)).hexdigest();current=key_id
            base={'seq':2,'previous':previous,'kind':'report','key_id':current,'report':safe}
            return _append_batch(fd,[start,{**base,'mac':_mac(_key(keys,current),base)}])
        if key_id is not None and key_id!=current:raise ValueError('KEY_ROTATION_REQUIRED')
        base={'seq':len(records)+1,'previous':previous,'kind':'report','key_id':current,'report':safe}
        return _append(fd,{**base,'mac':_mac(_key(keys,current),base)})
    finally:os.close(fd)

def rotate_authenticated(path,*,keys,new_key_id,trusted_head=None):
    fd=_open(path,readonly=True)
    os.close(fd)  # ensure existing history; never silently create one for rotation
    fd=_open(path)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        records,current,previous=_check(_read_locked(fd),keys,trusted_head=trusted_head)
        if not records or current==new_key_id:raise ValueError('INVALID_ROTATION')
        base={'seq':len(records)+1,'previous':previous,'kind':'rotate','from_key':current,'to_key':new_key_id}
        return _append(fd,{**base,'old_mac':_mac(_key(keys,current),base),'new_mac':_mac(_key(keys,new_key_id),base)})
    finally:os.close(fd)

def read_authenticated(path,*,keys,limit=100,trusted_head=None):
    if type(limit) is not int or not 1<=limit<=10000:raise ValueError('INVALID_LIMIT')
    try:fd=_open(path,readonly=True)
    except FileNotFoundError:
        if trusted_head is not None and trusted_head!=GENESIS:raise ValueError('TRUSTED_HEAD_MISMATCH')
        return {'status':'EMPTY','total':0,'records':[],'head_sha256':GENESIS,'cutover_authorized':False}
    try:
        fcntl.flock(fd,fcntl.LOCK_SH)
        records,current,head=_check(_read_locked(fd),keys,trusted_head=trusted_head)
        reports=[r for r in records if r['kind']=='report']
        return {'status':'AUTHENTICATED','total':len(reports),'records':reports[-limit:],'active_key_id':current,'head_sha256':head,'cutover_authorized':False}
    finally:os.close(fd)
