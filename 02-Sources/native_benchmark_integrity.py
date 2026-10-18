"""V191.9: fail-closed, hash-chained benchmark campaign journal.

Independent from the legacy JSONL history; no automatic trust migration.
"""
import hashlib
import hmac
import json
import os
import fcntl
from pathlib import Path
from native_benchmark_history import _safe_report

GENESIS='0'*64

def _canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')

def _read_locked(fd):
    os.lseek(fd,0,os.SEEK_SET)
    chunks=[]
    while True:
        chunk=os.read(fd,65536)
        if not chunk:break
        chunks.append(chunk)
        if sum(map(len,chunks))>20_000_000:raise ValueError('HISTORY_TOO_LARGE')
    raw=b''.join(chunks)
    if raw and not raw.endswith(b'\n'):raise ValueError('INCOMPLETE_HISTORY')
    return raw

def _validate(raw):
    prev=GENESIS;records=[]
    for number,line in enumerate(raw.splitlines(),1):
        try:
            item=json.loads(line)
            if set(item)!={'seq','previous_sha256','report','sha256'}:raise ValueError('INVALID_FIELDS')
            if item['seq']!=number or item['previous_sha256']!=prev:raise ValueError('BROKEN_CHAIN')
            report=_safe_report(item['report'])
            if report!=item['report']:raise ValueError('INVALID_REPORT')
            digest=hashlib.sha256(_canonical({'seq':number,'previous_sha256':prev,'report':report})).hexdigest()
            if not hmac.compare_digest(digest,item['sha256']):raise ValueError('INVALID_DIGEST')
            prev=digest;records.append(item)
        except (ValueError,TypeError,KeyError,UnicodeError) as exc:
            raise ValueError('CORRUPTED_HISTORY_RECORD') from exc
    return records

def _open(path,readonly=False):
    target=Path(path)
    if not readonly:target.parent.mkdir(parents=True,exist_ok=True)
    flags=(os.O_RDONLY if readonly else os.O_RDWR|os.O_CREAT)|os.O_NOFOLLOW
    return os.open(target,flags,0o600)

def append_verified(path,report):
    safe=_safe_report(report)
    fd=_open(path)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        records=_validate(_read_locked(fd))
        seq=len(records)+1;prev=records[-1]['sha256'] if records else GENESIS
        base={'seq':seq,'previous_sha256':prev,'report':safe}
        item={**base,'sha256':hashlib.sha256(_canonical(base)).hexdigest()}
        os.lseek(fd,0,os.SEEK_END)
        data=_canonical(item)+b'\n'
        while data:
            written=os.write(fd,data)
            if written<=0:raise OSError('SHORT_WRITE')
            data=data[written:]
        os.fsync(fd)
        return {'seq':seq,'sha256':item['sha256']}
    finally:os.close(fd)

def read_verified(path,limit=100):
    if type(limit) is not int or not 1<=limit<=10000:raise ValueError('INVALID_LIMIT')
    try:fd=_open(path,readonly=True)
    except FileNotFoundError:return {'status':'EMPTY','total':0,'records':[],'head_sha256':GENESIS,'cutover_authorized':False}
    try:
        fcntl.flock(fd,fcntl.LOCK_SH)
        records=_validate(_read_locked(fd))
        return {'status':'VERIFIED','total':len(records),'records':records[-limit:],'head_sha256':records[-1]['sha256'] if records else GENESIS,'cutover_authorized':False}
    finally:os.close(fd)
