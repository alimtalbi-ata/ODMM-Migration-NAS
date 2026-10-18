import json
import multiprocessing as mp
import pytest
from odmm_nas_acl_benchmark_v2156 import benchmark_existing_history,write_benchmark_report
from odmm_nas_acl_stream_v2154 import StreamingAuditHistory
from odmm_nas_acl_multiprocess_v2155 import SQLiteCASAnchor
from test_odmm_nas_acl_recovery_v2151 import signed

def test_benchmark_existing_125(tmp_path):
    h=StreamingAuditHistory(tmp_path/'audit.db',b'k'*32)
    for _ in range(125):h.record(signed())
    r=benchmark_existing_history(h.path,b'k'*32,page_size=23,batch_size=17,repeats=2)
    assert len(r['samples'])==2
    assert all(s['records_scanned']==125 and s['pages']==6 for s in r['samples'])
    assert r['cutover_authorized'] is False
    path=write_benchmark_report(r,tmp_path/'report.json')
    assert json.load(open(path))['qualification']=='LOCAL_ONLY_NOT_VENDOR_ATTESTED'
    with pytest.raises(FileExistsError):write_benchmark_report(r,path)

def test_tamper_refuses_benchmark(tmp_path):
    h=StreamingAuditHistory(tmp_path/'audit.db',b'k'*32)
    h.record(signed())
    with h._db() as db:db.execute("UPDATE acl_audit_history SET digest='tampered' WHERE seq=1")
    with pytest.raises(ValueError,match='AUDIT_INTEGRITY_FAILED'):benchmark_existing_history(h.path,b'k'*32)

def test_missing_db_refused(tmp_path):
    with pytest.raises(FileNotFoundError):benchmark_existing_history(tmp_path/'missing.db',b'k'*32)
    assert not (tmp_path/'missing.db').exists()

@pytest.mark.parametrize('params',[{'repeats':0},{'repeats':11},{'page_size':101},{'batch_size':0},{'max_records':100001}])
def test_invalid_bounds(tmp_path,params):
    p=tmp_path/'audit.db';StreamingAuditHistory(p,b'k'*32)
    with pytest.raises(ValueError):benchmark_existing_history(p,b'k'*32,**params)

def _cas_worker(args):
    path,gate,index=args
    gate.wait()
    return SQLiteCASAnchor(path).cas({'seq':0},{'seq':index})

def test_conflict_across_processes(tmp_path):
    p=str(tmp_path/'cas.db');store=SQLiteCASAnchor(p)
    assert store.cas(None,{'seq':0})
    with mp.get_context("spawn").Manager() as manager:
        gate=manager.Event()
        with mp.get_context("spawn").Pool(4) as pool:
            futures=[pool.apply_async(_cas_worker,((p,gate,i),)) for i in range(1,5)]
            gate.set()
            results=[f.get(timeout=30) for f in futures]
    assert results.count(True)==1
    assert store.read()['seq'] in (1,2,3,4)
