"""Transactional, fail-closed quarantine of reviewer approvals from offline drift evidence.

Quarantine does not revoke directory credentials or authorize a cutover.
"""
import json
import time
from human_approval_registry import ApprovalError, digest
from review_identity_policy import IdentityPolicyLedger

class QuarantinedReviewLedger(IdentityPolicyLedger):
    def __init__(self, path, *, issuer_secret):
        super().__init__(path, issuer_secret=issuer_secret)
        self.db.execute("""CREATE TABLE IF NOT EXISTS review_quarantines (
            migration_id TEXT PRIMARY KEY, evidence_hash TEXT NOT NULL,
            freshness_hash TEXT NOT NULL, reason_json TEXT NOT NULL,
            quarantined_at INTEGER NOT NULL)""")

    def quarantine(self, migration_id, readiness_bundle, freshness_bundle, *, now=None):
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        evidence=self._evidence(migration_id, readiness_bundle)
        if not isinstance(freshness_bundle,dict) or not isinstance(freshness_bundle.get('report'),dict):
            raise ApprovalError('INVALID_FRESHNESS_EVIDENCE')
        report=freshness_bundle['report']
        if freshness_bundle.get('sha256')!=digest(report) or report.get('schema')!='odmm.directory-freshness.v1':
            raise ApprovalError('INVALID_FRESHNESS_EVIDENCE')
        if report.get('cutover_authorized') is not False or report.get('directory_authenticated') is not False:
            raise ApprovalError('INVALID_FRESHNESS_EVIDENCE')
        reasons=report.get('reasons')
        if (report.get('status')!='REVIEW_REQUIRED' or not isinstance(reasons,list)
            or not reasons or any(not isinstance(r,str) or not r for r in reasons)):
            raise ApprovalError('QUARANTINE_REQUIRES_DRIFT')
        if report.get('now')!=stamp: raise ApprovalError('FRESHNESS_TIME_MISMATCH')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            if self.verify_journal()['status']!='CHAIN_INTACT_UNAUTHENTICATED':
                raise ApprovalError('AUDIT_CHAIN_TAMPERED')
            existing=self.db.execute('SELECT evidence_hash FROM dual_reviews WHERE migration_id=?',(migration_id,)).fetchall()
            if not existing: raise ApprovalError('NO_REVIEW_TO_QUARANTINE')
            if any(row[0]!=evidence for row in existing): raise ApprovalError('STALE_EVIDENCE')
            if self.db.execute('SELECT 1 FROM review_quarantines WHERE migration_id=?',(migration_id,)).fetchone():
                raise ApprovalError('ALREADY_QUARANTINED')
            self.db.execute('INSERT INTO review_quarantines VALUES (?,?,?,?,?)',
                (migration_id,evidence,freshness_bundle['sha256'],json.dumps(reasons,sort_keys=True),stamp))
            # Mark every review revoked; even if one was already revoked, preserve it.
            self.db.execute('UPDATE dual_reviews SET revoked_at=? WHERE migration_id=? AND revoked_at IS NULL',
                (stamp,migration_id))
            self._append_in_transaction(migration_id,'REVIEWS_QUARANTINED','directory-freshness-gate',evidence,stamp)
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        return {'status':'QUARANTINED_REVIEW_REQUIRED','cutover_authorized':False,'production_qualified':False}

    def assess(self, migration_id, bundle, *, now=None):
        if self.db.execute('SELECT 1 FROM review_quarantines WHERE migration_id=?',(migration_id,)).fetchone():
            return {'status':'QUARANTINED_REVIEW_REQUIRED','cutover_authorized':False,'production_qualified':False}
        return super().assess(migration_id,bundle,now=now)
