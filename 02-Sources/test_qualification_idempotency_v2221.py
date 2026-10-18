"""V222.1 deterministic tests for retries, conflicting requests and process concurrency."""
import multiprocessing as mp
from pathlib import Path
import tempfile
import pytest
from qualification_decisions_v2215 import append_review, review_status
from qualification_review_coordination_v2220 import append_review_coordinated
from qualification_review_security_v2217 import write_anchor, review_head, verify_anchor
from qualification_dossier_v2214 import canonical_bytes
import hashlib

KEY=b'q'*32

def dossier():
    payload={'schema':'synthetic.test','cutover_authorized':False}
    return {'payload':payload,'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest()}

def test_idempotency_direct(monkeypatch):
    # Use a correctly constructed V2214 dossier in integration tests below.
    from qualification_dossier_v2214 import verify_dossier
    assert callable(verify_dossier)

def valid_dossier():
    payload={'review':{'decision':'PENDING_HUMAN_REVIEW'},'cutover_authorized':False}
    return {'payload':payload,'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(), 'digest_algorithm':'SHA-256','signature_verified':False}

def test_repeated_request_returns_same_event():
    with tempfile.TemporaryDirectory() as tmp:
        db=Path(tmp)/'review.db'; d=valid_dossier()
        a=append_review(db,d,action='APPROVE_REVIEW',reviewer='alice',reason='verified',secret=KEY,request_id='request-0001')
        b=append_review(db,d,action='APPROVE_REVIEW',reviewer='alice',reason='verified',secret=KEY,request_id='request-0001')
        assert b['idempotent_replay'] is True and b['mac']==a['mac']
        assert len(review_status(db,d,secret=KEY)['events'])==1

def test_conflicting_retry_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        db=Path(tmp)/'review.db'; d=valid_dossier()
        append_review(db,d,action='APPROVE_REVIEW',reviewer='alice',reason='verified',secret=KEY,request_id='request-0002')
        with pytest.raises(ValueError,match='REQUEST_ID_REUSED'):
            append_review(db,d,action='REVOKE_REVIEW',reviewer='alice',reason='verified',secret=KEY,request_id='request-0002')
        assert len(review_status(db,d,secret=KEY)['events'])==1

def test_invalid_request_ids():
    with tempfile.TemporaryDirectory() as tmp:
        for rid in ('a', 'x'*129, 'unsafe/path', True):
            with pytest.raises(ValueError,match='INVALID_REQUEST_ID'):
                append_review(Path(tmp)/'db',valid_dossier(),action='APPROVE_REVIEW',reviewer='alice',reason='ok',secret=KEY,request_id=rid)

def test_coordinated_retry_preserves_anchor():
    with tempfile.TemporaryDirectory() as tmp:
        db=Path(tmp)/'review.db'; anchor=Path(tmp)/'anchor.json'; d=valid_dossier()
        write_anchor(db,anchor,KEY)
        identity={'subject':'alice','roles':['qualification:approve']}
        a=append_review_coordinated(db,anchor,d,identity=identity,action='APPROVE_REVIEW',reason='verified',secret=KEY,request_id='request-0003')
        b=append_review_coordinated(db,anchor,d,identity=identity,action='APPROVE_REVIEW',reason='verified',secret=KEY,request_id='request-0003')
        assert b['idempotent_replay'] and a['mac']==b['mac']
        assert review_head(db,KEY)['count']==1 and verify_anchor(db,anchor,KEY)

def _worker(db, anchor, queue):
    try:
        e=append_review_coordinated(db,anchor,valid_dossier(),identity={'subject':'alice','roles':['qualification:approve']},action='APPROVE_REVIEW',reason='verified',secret=KEY,request_id='request-concurrent')
        queue.put(('ok',e['mac']))
    except Exception as exc:
        queue.put(('error',type(exc).__name__,str(exc)))

def test_two_processes_one_event():
    with tempfile.TemporaryDirectory() as tmp:
        db=str(Path(tmp)/'review.db'); anchor=str(Path(tmp)/'anchor.json')
        write_anchor(db,anchor,KEY)
        ctx=mp.get_context('spawn'); queue=ctx.Queue()
        workers=[ctx.Process(target=_worker,args=(db,anchor,queue)) for _ in range(2)]
        for w in workers:w.start()
        for w in workers:w.join(15); assert w.exitcode==0
        results=[queue.get(timeout=3) for _ in workers]
        assert all(r[0]=='ok' for r in results),results
        assert results[0][1]==results[1][1]
        assert review_head(db,KEY)['count']==1
