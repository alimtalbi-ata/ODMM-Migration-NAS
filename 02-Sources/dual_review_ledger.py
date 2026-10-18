"""Offline two-role review ledger. Records are not production cutover authorization."""
import sqlite3
import time
from human_approval_registry import digest, ApprovalError

ROLES = ('security', 'operations')

class DualReviewLedger:
    def __init__(self, path):
        self.db=sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute("""CREATE TABLE IF NOT EXISTS dual_reviews (
          migration_id TEXT NOT NULL, role TEXT NOT NULL, reviewer TEXT NOT NULL,
          evidence_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
          revoked_at INTEGER, created_at INTEGER NOT NULL,
          PRIMARY KEY(migration_id,role))""")
    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()
    @staticmethod
    def _evidence(migration_id, bundle):
        if not isinstance(bundle,dict) or not isinstance(bundle.get('report'),dict):
            raise ApprovalError('INVALID_EVIDENCE')
        report=bundle['report']
        if (report.get('migration_id') != migration_id or bundle.get('sha256') != digest(report)
            or report.get('status') != 'PENDING_HUMAN_AND_LIVE_VERIFICATION'
            or report.get('cutover_authorized') is not False):
            raise ApprovalError('EVIDENCE_NOT_REVIEWABLE')
        return bundle['sha256']
    def record(self, migration_id, bundle, role, reviewer, ttl_seconds, *, now=None):
        if role not in ROLES: raise ApprovalError('INVALID_ROLE')
        if any(not isinstance(s,str) or not s.strip() or len(s)>128 for s in (migration_id,reviewer)):
            raise ApprovalError('INVALID_IDENTITY')
        if type(ttl_seconds) is not int or not 1<=ttl_seconds<=86400: raise ApprovalError('INVALID_TTL')
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        evidence_hash=self._evidence(migration_id,bundle)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            other=self.db.execute('SELECT DISTINCT reviewer,evidence_hash FROM dual_reviews WHERE migration_id=?',(migration_id,)).fetchall()
            if any(r[0]==reviewer for r in other): raise ApprovalError('SEPARATION_OF_DUTIES')
            if any(r[1]!=evidence_hash for r in other): raise ApprovalError('STALE_EVIDENCE')
            self.db.execute('INSERT INTO dual_reviews VALUES (?,?,?,?,?,NULL,?)',
                            (migration_id,role,reviewer,evidence_hash,stamp+ttl_seconds,stamp))
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            raise
        return {'status':'REVIEW_RECORDED_ONLY','cutover_authorized':False}
    def revoke(self,migration_id,role,*,now=None):
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0 or role not in ROLES: raise ApprovalError('INVALID_REVOCATION')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            n=self.db.execute('UPDATE dual_reviews SET revoked_at=? WHERE migration_id=? AND role=? AND revoked_at IS NULL',(stamp,migration_id,role)).rowcount
            if n!=1: raise ApprovalError('REVIEW_NOT_ACTIVE')
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            raise
    def assess(self,migration_id,bundle,*,now=None):
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        try: h=self._evidence(migration_id,bundle)
        except ApprovalError: return {'status':'INVALID_EVIDENCE','cutover_authorized':False}
        rows=self.db.execute('SELECT role,reviewer,evidence_hash,expires_at,revoked_at FROM dual_reviews WHERE migration_id=?',(migration_id,)).fetchall()
        by_role={r[0]:r for r in rows}
        if any(r[2]!=h for r in rows): status='STALE_EVIDENCE'
        elif any(r[4] is not None for r in rows): status='REVOKED'
        elif any(stamp>=r[3] for r in rows): status='EXPIRED'
        elif not all(role in by_role for role in ROLES): status='PENDING_SECOND_REVIEW'
        elif len({r[1] for r in rows})!=2: status='SEPARATION_OF_DUTIES_FAILURE'
        else: status='DUAL_REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED'
        return {'status':status,'cutover_authorized':False,'production_qualified':False}
