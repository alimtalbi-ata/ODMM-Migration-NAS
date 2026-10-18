import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from odmm_session_registry_v2062 import SessionRegistry

def test_issue_resolve_revoke(tmp_path):
    reg=SessionRegistry(tmp_path/'s.db',key=b'k'*32)
    token=reg.issue('alice','operator')
    assert reg.resolve(token)=={'actor':'alice','role':'operator'}
    with sqlite3.connect(tmp_path/'s.db') as db:
        assert token not in str(db.execute('select * from sessions').fetchall())
    assert reg.revoke(token) is True
    assert reg.revoke(token) is False
    assert reg.resolve(token) is None

def test_expiry_cleanup(tmp_path):
    now=[100.]
    reg=SessionRegistry(tmp_path/'s.db',key=b'k'*32,clock=lambda:now[0])
    token=reg.issue('bob','admin',ttl=10)
    now[0]=110.
    assert reg.resolve(token) is None
    assert reg.cleanup()==1

def test_invalid_input(tmp_path):
    with pytest.raises(ValueError):SessionRegistry(tmp_path/'s.db',key=b'weak')
    reg=SessionRegistry(tmp_path/'s.db',key=b'k'*32)
    with pytest.raises(ValueError):reg.issue('alice','operator',ttl=0)
    with pytest.raises(ValueError):reg.issue('alice','superuser')
    assert reg.resolve('bad') is None

def test_concurrent_revocation(tmp_path):
    db=tmp_path/'s.db'; key=b'k'*32
    reg=SessionRegistry(db,key=key); token=reg.issue('alice','operator')
    with ThreadPoolExecutor(max_workers=10) as pool:
        outcomes=list(pool.map(lambda _:SessionRegistry(db,key=key).revoke(token),range(10)))
    assert outcomes.count(True)==1
    assert reg.resolve(token) is None

def test_wrong_key_cannot_resolve(tmp_path):
    db=tmp_path/'s.db'; a=SessionRegistry(db,key=b'a'*32)
    token=a.issue('alice','operator')
    assert SessionRegistry(db,key=b'b'*32).resolve(token) is None
