"""Fail-closed offline directory snapshot -> reconciliation reviewer grants.

Not an authentication provider. Snapshot authenticity is outside this module.
"""
from directory_snapshot_adapter import normalize_directory_export
from directory_sync_journal import digest
from ldaps_rbac_reconciliation import ReconciliationRBACError

class DirectoryRBACBridge:
    def __init__(self, rbac):
        self.rbac=rbac; self.db=rbac.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_rbac_directory_versions (
          id INTEGER PRIMARY KEY CHECK(id=1), source TEXT NOT NULL, version TEXT NOT NULL,
          snapshot_hash TEXT NOT NULL, generation INTEGER NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_rbac_grant_audit (
          seq INTEGER PRIMARY KEY, generation INTEGER NOT NULL, source TEXT NOT NULL,
          version TEXT NOT NULL, snapshot_hash TEXT NOT NULL, changed TEXT NOT NULL,
          at INTEGER NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_rbac_directory_freshness (
          id INTEGER PRIMARY KEY CHECK(id=1), synced_at INTEGER NOT NULL, max_age_seconds INTEGER NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_rbac_review_invalidations (
          event_id TEXT NOT NULL, request_id TEXT NOT NULL, observation_hash TEXT NOT NULL,
          generation INTEGER NOT NULL, reason TEXT NOT NULL,
          PRIMARY KEY(event_id,request_id,observation_hash))''')

    def verify(self):
        prev='GENESIS'; rows=self.db.execute('SELECT * FROM ldaps_rbac_grant_audit ORDER BY seq').fetchall()
        for i,(seq,g,src,ver,sha,changed,at,old,h) in enumerate(rows,1):
            obj=dict(seq=seq,generation=g,source=src,version=ver,snapshot_hash=sha,changed=changed,at=at,previous_hash=prev)
            if seq!=i or old!=prev or digest(obj)!=h:raise ReconciliationRBACError('DIRECTORY_GRANT_AUDIT_TAMPERED')
            prev=h
        return {'count':len(rows),'last_hash':prev}

    def apply(self, export, *, now, expected_previous_digest=None):
        if type(now)!=int or now<0:raise ReconciliationRBACError('INVALID_TIMESTAMP')
        bundle=normalize_directory_export(export)
        sha=bundle['sha256']; norm=bundle['normalized']
        new={r['reviewer']:(r['role'].upper() if r['role'] else 'SECURITY',int(r['active'])) for r in norm['accounts']}
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.verify(); self.rbac.verify()
            previous=self.db.execute('SELECT source,version,snapshot_hash,generation FROM ldaps_rbac_directory_versions WHERE id=1').fetchone()
            if (previous is None and expected_previous_digest is not None) or (previous is not None and expected_previous_digest!=previous[2]):
                raise ReconciliationRBACError('DIRECTORY_SNAPSHOT_CONFLICT')
            if previous and previous[1]==norm['version'] and previous[2]!=sha:raise ReconciliationRBACError('DIRECTORY_VERSION_REUSED')
            old=dict((r,(role,active)) for r,role,active in self.db.execute('SELECT reviewer,role,active FROM ldaps_rbac_users'))
            changed=sorted(k for k in set(old)|set(new) if old.get(k)!=new.get(k))
            generation=previous[3]+1 if previous else 1
            self.db.execute('UPDATE ldaps_rbac_users SET active=0')
            for reviewer,(role,active) in new.items():
                self.db.execute('INSERT INTO ldaps_rbac_users VALUES (?,?,?) ON CONFLICT(reviewer) DO UPDATE SET role=excluded.role,active=excluded.active',(reviewer,role,active))
            # Invalidate any partially/fully completed review involving a changed identity.
            # No deletion of historical evidence.
            if changed:
                placeholders=','.join('?' for _ in changed)
                impacted=self.db.execute('SELECT DISTINCT event_id,request_id,observation_hash FROM ldaps_rbac_decisions WHERE reviewer IN ('+placeholders+')',changed).fetchall()
                for event,request,obs in impacted:
                    self.db.execute('INSERT OR REPLACE INTO ldaps_rbac_review_invalidations VALUES (?,?,?,?,?)',(event,request,obs,generation,'DIRECTORY_GRANT_CHANGED'))
            self.db.execute('INSERT INTO ldaps_rbac_directory_versions VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET source=excluded.source,version=excluded.version,snapshot_hash=excluded.snapshot_hash,generation=excluded.generation',(norm['source'],norm['version'],sha,generation))
            last=self.db.execute('SELECT seq,event_hash FROM ldaps_rbac_grant_audit ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1; prev=last[1] if last else 'GENESIS'
            changed_string=','.join(changed)
            obj=dict(seq=seq,generation=generation,source=norm['source'],version=norm['version'],snapshot_hash=sha,changed=changed_string,at=now,previous_hash=prev)
            h=digest(obj)
            self.db.execute('INSERT INTO ldaps_rbac_grant_audit VALUES (?,?,?,?,?,?,?,?,?)',(seq,generation,norm['source'],norm['version'],sha,changed_string,now,prev,h))
            freshness=self.db.execute('SELECT max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
            if freshness:
                self.db.execute('UPDATE ldaps_rbac_directory_freshness SET synced_at=? WHERE id=1',(now,))
            self.db.execute('COMMIT')
            return dict(status='OFFLINE_RBAC_GRANTS_SYNCED',generation=generation,snapshot_sha256=sha,changed_reviewers=changed,review_invalidations=len(impacted) if changed else 0,authenticated=False,execution_authorized=False,cutover_authorized=False)
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
