"""Atomic offline directory synchronization and conservative review quarantine.

Untrusted snapshots cannot authorize cutover. Every changed reviewer with an
existing approval quarantines the migration. No implicit release from quarantine.
"""
import json
import re
from directory_snapshot_adapter import normalize_directory_export
from human_approval_registry import ApprovalError
from review_quarantine import QuarantinedReviewLedger

class AtomicDirectoryQuarantineLedger(QuarantinedReviewLedger):
    def __init__(self, path, *, issuer_secret):
        super().__init__(path, issuer_secret=issuer_secret)
        self.db.execute("""CREATE TABLE IF NOT EXISTS directory_sync_state (
            source TEXT PRIMARY KEY, version TEXT NOT NULL, digest TEXT NOT NULL)""")

    def synchronize_and_quarantine(self, export, *, expected_previous_digest=None, now, _within_transaction=False):
        bundle = normalize_directory_export(export)
        if type(now) is not int or now < 0:
            raise ApprovalError('INVALID_TIME')
        if expected_previous_digest is not None and (not isinstance(expected_previous_digest,str)
            or not re.fullmatch('[0-9a-f]{64}', expected_previous_digest)):
            raise ApprovalError('INVALID_EXPECTED_DIGEST')
        source=bundle['normalized']['source']; version=bundle['normalized']['version']
        proposed={r['reviewer']:r for r in bundle['normalized']['accounts']}
        try:
            if not _within_transaction: self.db.execute('BEGIN IMMEDIATE')
            if self.verify_journal()['status']!='CHAIN_INTACT_UNAUTHENTICATED':
                raise ApprovalError('AUDIT_CHAIN_TAMPERED')
            old=self.db.execute('SELECT version,digest FROM directory_sync_state WHERE source=?',(source,)).fetchone()
            if (old is None and expected_previous_digest is not None) or (old is not None and old[1]!=expected_previous_digest):
                raise ApprovalError('DIRECTORY_SNAPSHOT_CONFLICT')
            if old and old[0]==version and old[1]!=bundle['sha256']:
                raise ApprovalError('DIRECTORY_VERSION_REUSED')
            previous={r[0]:(r[1],bool(r[2])) for r in self.db.execute('SELECT reviewer,role,active FROM reviewer_directory')}
            changed=set()
            for reviewer in set(previous)|set(proposed):
                r=proposed.get(reviewer)
                candidate=(r['role'] or 'security',r['active']) if r else None
                if previous.get(reviewer)!=candidate: changed.add(reviewer)
            # Any migration reviewed by a changed identity is conservatively quarantined.
            impacted=sorted({r[0] for r in self.db.execute('SELECT migration_id,reviewer FROM dual_reviews') if r[1] in changed})
            self.db.execute('UPDATE reviewer_directory SET active=0')
            for row in bundle['normalized']['accounts']:
                self.db.execute("""INSERT INTO reviewer_directory(reviewer,role,active,directory_version)
                    VALUES(?,?,?,?) ON CONFLICT(reviewer) DO UPDATE SET role=excluded.role,
                    active=excluded.active,directory_version=excluded.directory_version""",
                    (row['reviewer'],row['role'] or 'security',int(row['active']),version))
            self.db.execute("""INSERT INTO directory_sync_state(source,version,digest) VALUES(?,?,?)
                ON CONFLICT(source) DO UPDATE SET version=excluded.version,digest=excluded.digest""",
                (source,version,bundle['sha256']))
            for migration in impacted:
                if self.db.execute('SELECT 1 FROM review_quarantines WHERE migration_id=?',(migration,)).fetchone():
                    continue
                evidence_rows=self.db.execute('SELECT DISTINCT evidence_hash FROM dual_reviews WHERE migration_id=?',(migration,)).fetchall()
                if len(evidence_rows)!=1: raise ApprovalError('CONFLICTING_REVIEW_EVIDENCE')
                evidence=evidence_rows[0][0]
                self.db.execute('INSERT INTO review_quarantines VALUES (?,?,?,?,?)',
                    (migration,evidence,bundle['sha256'],json.dumps(['DIRECTORY_REVIEWER_CHANGED'],sort_keys=True),now))
                self.db.execute('UPDATE dual_reviews SET revoked_at=? WHERE migration_id=? AND revoked_at IS NULL',(now,migration))
                self._append_in_transaction(migration,'REVIEWS_QUARANTINED','directory-atomic-sync',evidence,now)
            if not _within_transaction: self.db.execute('COMMIT')
        except BaseException:
            if not _within_transaction and self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        return {'status':'OFFLINE_DIRECTORY_APPLIED_WITH_QUARANTINE',
                'sha256':bundle['sha256'],'quarantined_migrations':impacted,
                'directory_authenticated':False,'cutover_authorized':False,
                'production_qualified':False}
