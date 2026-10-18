import multiprocessing as mp
import pytest
from odmm_nas_acl_multiprocess_v2155 import SQLiteCASAnchor, benchmark_history_pagination
from odmm_nas_acl_stream_v2154 import StreamingAuditHistory
from test_odmm_nas_acl_recovery_v2151 import signed

def _race(args):
    path, expected, replacement, gate=args
    gate.wait()
    return SQLiteCASAnchor(path).cas(expected,replacement)

def test_cas_cross_process_one_winner(tmp_path):
    path=str(tmp_path/'external-anchor.sqlite')
    anchor=SQLiteCASAnchor(path)
    assert anchor.cas(None,{'seq':0})
    with mp.get_context('spawn').Manager() as manager:
        gate=manager.Event()
        with mp.get_context('spawn').Pool(4) as pool:
            tasks=[pool.apply_async(_race,((path,{'seq':0},{'seq':i},gate),)) for i in range(1,5)]
            gate.set()
            results=[x.get(timeout=20) for x in tasks]
    assert results.count(True)==1
    assert anchor.read()['seq'] in (1,2,3,4)

def test_cas_restart_conflict_and_bootstrap(tmp_path):
    path=tmp_path/'anchor.sqlite'
    first=SQLiteCASAnchor(path)
    assert first.cas(None,{'seq':0})
    second=SQLiteCASAnchor(path)
    assert not second.cas(None,{'seq':1})
    assert second.cas({'seq':0},{'seq':1})
    assert not first.cas({'seq':0},{'seq':2})
    assert first.read()=={'seq':1}

def test_bounded_pagination_real_rows(tmp_path):
    history=StreamingAuditHistory(tmp_path/'history.sqlite',b'k'*32)
    for _ in range(113):history.record(signed())
    result=benchmark_history_pagination(history,records=1000,page_size=25)
    assert result['records_scanned']==113 and result['pages']==5
    assert result['cutover_authorized'] is False

@pytest.mark.parametrize('n,size',[(0,10),(100001,10),(True,10),(10,0),(10,101)])
def test_invalid_benchmark_bounds(tmp_path,n,size):
    history=StreamingAuditHistory(tmp_path/'history.sqlite',b'k'*32)
    with pytest.raises(ValueError):benchmark_history_pagination(history,records=n,page_size=size)

def test_corruption_blocks_benchmark(tmp_path):
    history=StreamingAuditHistory(tmp_path/'history.sqlite',b'k'*32)
    history.record(signed())
    with history._db() as db:db.execute("UPDATE acl_audit_history SET digest='0' WHERE seq=1")
    with pytest.raises(ValueError):benchmark_history_pagination(history)
