"""Transactional offline review ledger; NOT a production cutover authorization."""
import hashlib
import json
import sqlite3
import time
from pathlib import Path

class ApprovalError(ValueError): pass

def digest(report):
    return hashlib.sha256(json.dumps(report, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

class ApprovalRegistry:
    def __init__(self, path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute("""CREATE TABLE IF NOT EXISTS reviews (
            review_id TEXT PRIMARY KEY, migration_id TEXT NOT NULL,
            evidence_hash TEXT NOT NULL, reviewer TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            revoked_at INTEGER, reason TEXT,
            CHECK(expires_at > created_at))""")
    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

    def submit(self, review_id, migration_id, readiness_bundle, reviewer, ttl_seconds, *, now=None):
        if not isinstance(readiness_bundle, dict) or not isinstance(readiness_bundle.get('report'),dict):
            raise ApprovalError('INVALID_READINESS')
        report=readiness_bundle['report']
        if readiness_bundle.get('sha256') != digest(report) or report.get('migration_id') != migration_id:
            raise ApprovalError('EVIDENCE_MISMATCH')
        if report.get('status') != 'PENDING_HUMAN_AND_LIVE_VERIFICATION' or report.get('cutover_authorized') is not False:
            raise ApprovalError('READINESS_NOT_REVIEWABLE')
        if any(not isinstance(x,str) or not x.strip() or len(x)>128 for x in (review_id,migration_id,reviewer)):
            raise ApprovalError('INVALID_IDENTITY')
        if type(ttl_seconds) is not int or not 1<=ttl_seconds<=86400:
            raise ApprovalError('INVALID_TTL')
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('INSERT INTO reviews VALUES (?,?,?,?,?,?,NULL,NULL)',
                            (review_id,migration_id,readiness_bundle['sha256'],reviewer,stamp,stamp+ttl_seconds))
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            raise
        return {'review_id':review_id,'status':'RECORDED_REVIEW_ONLY','cutover_authorized':False}

    def revoke(self, review_id, reason, *, now=None):
        if not isinstance(reason,str) or not reason.strip() or len(reason)>256: raise ApprovalError('INVALID_REASON')
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            changed=self.db.execute('UPDATE reviews SET revoked_at=?,reason=? WHERE review_id=? AND revoked_at IS NULL',
                                    (stamp,reason,review_id)).rowcount
            if changed!=1: raise ApprovalError('REVIEW_NOT_ACTIVE')
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            raise

    def check(self, review_id, migration_id, readiness_bundle, *, now=None):
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        row=self.db.execute('SELECT migration_id,evidence_hash,expires_at,revoked_at FROM reviews WHERE review_id=?', (review_id,)).fetchone()
        status='MISSING'
        if row:
            if row[0]!=migration_id or not isinstance(readiness_bundle,dict) or not isinstance(readiness_bundle.get('report'),dict) or readiness_bundle.get('sha256')!=digest(readiness_bundle['report']) or row[1]!=readiness_bundle['sha256']:
                status='EVIDENCE_CHANGED'
            elif row[3] is not None: status='REVOKED'
            elif stamp>=row[2]: status='EXPIRED'
            else: status='REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED'
        return {'review_id':review_id,'status':status,'cutover_authorized':False,'production_qualified':False}
