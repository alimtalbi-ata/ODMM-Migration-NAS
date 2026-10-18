"""Deterministic multi-process CAS contention and rollback checks."""
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
from odmm_nas_acl_multiprocess_v2155 import SQLiteCASAnchor

def _try_cas(args):
    path, expected, new = args
    return SQLiteCASAnchor(path).cas(expected, new)

def test_cas_stress_20_rounds(tmp_path):
    path=str(tmp_path/'anchor.sqlite')
    a=SQLiteCASAnchor(path)
    assert a.cas(None, {'seq':0})
    with ProcessPoolExecutor(max_workers=4, mp_context=mp.get_context("spawn")) as pool:
        for seq in range(20):
            outcomes=list(pool.map(_try_cas,[(path,{'seq':seq},{'seq':seq+1})]*8))
            assert sum(outcomes)==1, (seq,outcomes)
            assert a.read()=={'seq':seq+1}

def test_cas_invalid_payload_does_not_mutate(tmp_path):
    a=SQLiteCASAnchor(tmp_path/'anchor.sqlite')
    assert a.cas(None, {'seq':1})
    try:a.cas({'seq':1},{'not_json':object()})
    except TypeError:pass
    else:raise AssertionError('expected serialization failure')
    assert a.read()=={'seq':1}
    assert a.cas({'seq':1},{'seq':2})
