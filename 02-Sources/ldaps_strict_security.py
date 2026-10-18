"""Persistent, opt-in fail-closed mode for human reconciliation decisions.

An application-level guard, not protection against a privileged SQLite writer.
"""
from ldaps_rbac_reconciliation import ReconciliationRBACError
from ldaps_security_startup import verify_startup

class StrictSecurityMode:
    def __init__(self, rbac):
        self.rbac=rbac
        self.db=rbac.db
        self.db.execute('CREATE TABLE IF NOT EXISTS ldaps_strict_security (id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL CHECK(enabled=1), enabled_at INTEGER NOT NULL)')

    def enabled(self):
        return self.db.execute('SELECT enabled FROM ldaps_strict_security WHERE id=1').fetchone() is not None

    def enable(self, *, now):
        if type(now) is not int or now<0:raise ReconciliationRBACError('INVALID_TIMESTAMP')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            verify_startup(self.rbac,now=now,require_audited_policy=True)
            if self.enabled():raise ReconciliationRBACError('STRICT_MODE_ALREADY_ENABLED')
            self.db.execute('INSERT INTO ldaps_strict_security VALUES (1,1,?)',(now,))
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
        return {'status':'STRICT_SECURITY_ENABLED','cutover_authorized':False,'execution_authorized':False}

    def guard(self, *, now):
        if not self.enabled():return {'status':'LEGACY_MODE','strict':False}
        result=verify_startup(self.rbac,now=now,require_audited_policy=True)
        return {**result,'strict':True}
