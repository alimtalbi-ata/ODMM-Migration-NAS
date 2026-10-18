"""V216.0 regression for cross-process write serialization."""
import sqlite3, threading, time
from odmm_nas_acl_verified_page_v2158 import verified_page
from test_odmm_nas_acl_operations_v2157 import fixture
from test_odmm_nas_acl_recovery_v2151 import signed

def test_guard_blocks_independent_sqlite_writer(tmp_path, monkeypatch):
    history, store, anchored = fixture(tmp_path)
    anchored.record(signed())
    entered=threading.Event(); release=threading.Event()
    original=anchored.verify
    def delayed():
        entered.set()
        assert release.wait(5)
        return original()
    monkeypatch.setattr(anchored,'verify',delayed)
    output=[]
    reader=threading.Thread(target=lambda:output.append(verified_page(anchored,limit=1)))
    reader.start()
    assert entered.wait(5)
    with sqlite3.connect(history.path,timeout=0.1) as db:
        try: db.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as e: assert 'locked' in str(e)
        else: raise AssertionError('Independent writer unexpectedly admitted')
    release.set();reader.join(5)
    assert not reader.is_alive() and output[0]['verified_head_seq']==1

def test_v2160_fail_closed(tmp_path):
    h,store,a=fixture(tmp_path)
    h.record(signed())
    try:verified_page(a)
    except RuntimeError as e: assert str(e)=='AUDIT_UNAVAILABLE'
    else:raise AssertionError('Unanchored history was served')
