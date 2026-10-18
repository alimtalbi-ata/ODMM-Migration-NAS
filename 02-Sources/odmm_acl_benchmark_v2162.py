"""Repeatable ACL audit-chain benchmark, synthetic signed exports only.
Author: Abdelhalim Talbi. Not vendor or production qualification.
"""
import argparse, json, os, tempfile, time, hashlib, hmac
from pathlib import Path
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_export_v2148 import canonical


def benchmark(count, *, directory=None):
    if type(count) is not int or count < 1 or count > 100000: raise ValueError('INVALID_COUNT')
    key=b'odmm-benchmark-key-not-for-production-use-123456789'
    with tempfile.TemporaryDirectory(dir=directory) as temp:
        history=AuditHistory(Path(temp)/'acl.db',key)
        payload={'schema':'odmm.nas.acl.audit.export.v2148','protocol':'NFS4','reports':[],'cutover_authorized':False}
        payload['payload_sha256']=hashlib.sha256(canonical(payload)).hexdigest()
        document={**payload,'signature':hmac.new(key,canonical(payload),hashlib.sha256).hexdigest()}
        start=time.perf_counter()
        for _ in range(count): history.record(document)
        insert_seconds=time.perf_counter()-start
        start=time.perf_counter()
        valid=history.verify_chain()
        verify_seconds=time.perf_counter()-start
        if not valid: raise RuntimeError('BENCHMARK_CHAIN_INVALID')
        start=time.perf_counter(); cursor=0; pages=0; read=0
        while True:
            page=history.page(cursor=cursor,limit=100)
            read+=len(page['items']); pages+=1
            if page['next_cursor'] is None:break
            cursor=page['next_cursor']
        page_seconds=time.perf_counter()-start
        if read!=count:raise RuntimeError('BENCHMARK_PAGE_MISMATCH')
        return {'schema':'odmm.acl.benchmark.v2162','synthetic':True,'records':count,
                'insert_seconds':round(insert_seconds,4),'verify_seconds':round(verify_seconds,4),
                'page_seconds':round(page_seconds,4),'pages':pages,'verified':valid,
                'platform':os.name,'vendor_qualified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--count',type=int,default=10000)
    args=p.parse_args();print(json.dumps(benchmark(args.count),indent=2))
