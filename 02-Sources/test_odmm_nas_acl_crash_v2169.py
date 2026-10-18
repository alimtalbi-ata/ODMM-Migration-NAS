"""Crash boundaries for audit WAL and independent CAS anchor. Author: Abdelhalim Talbi."""
import multiprocessing as mp
import os
import sqlite3
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_recovery_v2151 import RecoverableAnchoredHistory
from odmm_nas_acl_multiprocess_v2155 import SQLiteCASAnchor
from test_odmm_nas_acl_snapshot_v2163 import KEY, document


def _service(db, anchor):
    store=SQLiteCASAnchor(anchor)
    def write(value):
        if not store.cas(store.read(), value):
            raise RuntimeError('CAS_CONFLICT')
    return RecoverableAnchoredHistory(AuditHistory(db, KEY),read_anchor=store.read,write_anchor=write,anchor_key=KEY)


def _crash_inside_uncommitted(db):
    # A hard process exit while a SQLite IMMEDIATE transaction is open.
    conn=sqlite3.connect(db, isolation_level=None)
    conn.execute('BEGIN IMMEDIATE')
    conn.execute("UPDATE acl_audit_history SET digest='corrupted' WHERE seq=1")
    os._exit(73)


def _crash_after_local_commit(db):
    AuditHistory(db, KEY).record(document())
    os._exit(74)


def _spawn(target, db, expected):
    process=mp.get_context('spawn').Process(target=target,args=(db,))
    process.start();process.join(25)
    if process.is_alive():
        process.terminate();process.join(5)
        raise AssertionError('CRASH_WORKER_TIMEOUT')
    assert process.exitcode==expected


def test_crash_before_commit_rolls_back_and_anchor_remains_consistent(tmp_path):
    db=str(tmp_path/'history.sqlite'); anchor=str(tmp_path/'anchor.sqlite')
    service=_service(db,anchor);service.bootstrap_empty();service.record(document())
    _spawn(_crash_inside_uncommitted,db,73)
    restarted=_service(db,anchor)
    assert restarted.inspect_recovery()['state']=='CONSISTENT'
    assert restarted.verify() is True
    assert restarted.history.page()['items'][0]['seq']==1


def test_crash_after_local_commit_requires_explicit_reconciliation(tmp_path):
    db=str(tmp_path/'history.sqlite');anchor=str(tmp_path/'anchor.sqlite')
    service=_service(db,anchor);service.bootstrap_empty();service.record(document())
    _spawn(_crash_after_local_commit,db,74)
    restarted=_service(db,anchor)
    assert restarted.inspect_recovery()=={'state':'PENDING_ANCHOR','recoverable':True,'anchor_seq':1,'local_seq':2}
    assert restarted.verify() is False
    assert SQLiteCASAnchor(anchor).read()['seq']==1
    try:
        restarted.reconcile_explicit(expected_anchor_seq=1,expected_local_seq=2,approved=False)
    except ValueError as exc:
        assert str(exc)=='RECOVERY_APPROVAL_REQUIRED'
    else:
        raise AssertionError('MISSING_OPERATOR_APPROVAL')
    assert restarted.reconcile_explicit(expected_anchor_seq=1,expected_local_seq=2,approved=True)['state']=='RECOVERED'
    assert restarted.verify() is True
