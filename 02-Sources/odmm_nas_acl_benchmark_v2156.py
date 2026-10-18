"""Reproducible, read-only NAS ACL audit benchmark. Author: Abdelhalim Talbi.
Never generates hardware qualification or writes audit records.
"""
import json
import sqlite3
import statistics
import time
from pathlib import Path
from odmm_nas_acl_stream_v2154 import StreamingAuditHistory

def benchmark_existing_history(path, key, *, page_size=100, batch_size=256, repeats=3, max_records=100000):
    if type(repeats) is not int or not 1<=repeats<=10:raise ValueError('INVALID_REPEATS')
    if type(max_records) is not int or not 1<=max_records<=100000:raise ValueError('INVALID_MAX_RECORDS')
    if type(page_size) is not int or not 1<=page_size<=100:raise ValueError('INVALID_PAGE_SIZE')
    if type(batch_size) is not int or not 1<=batch_size<=4096:raise ValueError('INVALID_BATCH_SIZE')
    if not Path(path).is_file():raise FileNotFoundError('HISTORY_NOT_FOUND')
    history=StreamingAuditHistory(path,key)
    samples=[]
    for _ in range(repeats):
        start=time.perf_counter()
        if not history.verify_chain(batch_size=batch_size):raise ValueError('AUDIT_INTEGRITY_FAILED')
        verification=time.perf_counter()-start
        start=time.perf_counter(); cursor=0; seen=0; pages=0
        while seen<max_records:
            result=history.page(cursor=cursor,limit=min(page_size,max_records-seen))
            items=result['items']
            if not items:break
            if any(type(item['seq']) is not int or item['seq']<=cursor for item in items):raise ValueError('INVALID_PAGINATION')
            seen+=len(items); pages+=1; cursor=items[-1]['seq']
        samples.append({'verification_seconds':round(verification,6),'pagination_seconds':round(time.perf_counter()-start,6),'records_scanned':seen,'pages':pages})
    return {'schema':'odmm.nas.acl.benchmark.v2156','author':'Abdelhalim Talbi','environment':'local-existing-sqlite','qualification':'LOCAL_ONLY_NOT_VENDOR_ATTESTED','repeats':repeats,'page_size':page_size,'batch_size':batch_size,'max_records':max_records,'samples':samples,'median_verification_seconds':round(statistics.median(s['verification_seconds'] for s in samples),6),'median_pagination_seconds':round(statistics.median(s['pagination_seconds'] for s in samples),6),'cutover_authorized':False}

def write_benchmark_report(report, destination):
    if report.get('schema')!='odmm.nas.acl.benchmark.v2156' or report.get('cutover_authorized') is not False:raise ValueError('INVALID_REPORT')
    dest=Path(destination); dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('x',encoding='utf-8') as f:json.dump(report,f,sort_keys=True,indent=2)
    return str(dest)
