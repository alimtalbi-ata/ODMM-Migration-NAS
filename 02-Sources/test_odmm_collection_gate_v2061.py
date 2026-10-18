import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from odmm_collection_gate_v2061 import TransactionalSecurityGate

PARAMS=dict(actor='alice',role='operator',origin='https://odmm.example',expected_origin='https://odmm.example',csrf_cookie='a'*64,csrf_header='a'*64)
def test_multi_worker_limit(tmp_path):
    db=tmp_path/'gate.db'
    gates=[TransactionalSecurityGate(db,max_requests=3) for _ in range(12)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes=list(pool.map(lambda g:g.check(**PARAMS),gates))
    assert outcomes.count('ALLOW')==3
    assert outcomes.count('DENY_RATE')==9
    with sqlite3.connect(db) as conn:
        assert conn.execute('select count(*) from audit').fetchone()[0]==12
        assert conn.execute('select count(*) from rate').fetchone()[0]==3

def test_origin_path_rejected(tmp_path):
    gate=TransactionalSecurityGate(tmp_path/'a.db')
    assert gate.check(**{**PARAMS,'origin':'https://odmm.example/path'})=='DENY_CSRF'

def test_roles(tmp_path):
    gate=TransactionalSecurityGate(tmp_path/'a.db')
    assert gate.check(**{**PARAMS,'role':'viewer'})=='DENY_RBAC'

def test_rate_window(tmp_path):
    now=[1000.]
    gate=TransactionalSecurityGate(tmp_path/'a.db',max_requests=1,interval=60,clock=lambda:now[0])
    assert gate.check(**PARAMS)=='ALLOW'
    assert gate.check(**PARAMS)=='DENY_RATE'
    now[0]+=61
    assert gate.check(**PARAMS)=='ALLOW'

def test_invalid_limits(tmp_path):
    import pytest
    with pytest.raises(ValueError):TransactionalSecurityGate(tmp_path/'a.db',max_requests=0)
