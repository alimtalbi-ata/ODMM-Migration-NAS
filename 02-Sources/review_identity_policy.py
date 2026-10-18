"""Offline RBAC issuer-key lifecycle and signed reviewer directory snapshots.
No AD/LDAP network authentication; trusted provisioning is an external dependency.
"""
import hashlib, hmac, json, re
from human_approval_registry import ApprovalError
from authenticated_review_ledger import AuthenticatedReviewLedger, _payload

IDENT = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
ROLES = frozenset(('security','operations'))

def _id(v):
    if not isinstance(v,str) or not IDENT.fullmatch(v): raise ApprovalError('INVALID_IDENTIFIER')
    return v

class IdentityPolicyLedger(AuthenticatedReviewLedger):
    def __init__(self, path, *, issuer_secret):
        super().__init__(path, issuer_secret=issuer_secret)
        self.db.execute("""CREATE TABLE IF NOT EXISTS issuer_keys (
            key_id TEXT PRIMARY KEY, secret BLOB NOT NULL, valid_from INTEGER NOT NULL,
            valid_until INTEGER NOT NULL, revoked_at INTEGER)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS reviewer_directory (
            reviewer TEXT PRIMARY KEY, role TEXT NOT NULL, active INTEGER NOT NULL,
            directory_version TEXT NOT NULL)""")

    def provision_key(self, key_id, secret, *, valid_from, valid_until):
        _id(key_id)
        if not isinstance(secret,bytes) or len(secret)<32: raise ApprovalError('INVALID_ISSUER_KEY')
        if any(type(x) is not int for x in (valid_from,valid_until)) or not 0<=valid_from<valid_until:
            raise ApprovalError('INVALID_KEY_WINDOW')
        with self.db:
            self.db.execute('INSERT INTO issuer_keys VALUES (?,?,?,?,NULL)',(key_id,secret,valid_from,valid_until))

    def revoke_key(self, key_id, *, now):
        _id(key_id)
        if type(now) is not int or now<0: raise ApprovalError('INVALID_TIME')
        with self.db:
            cur=self.db.execute('UPDATE issuer_keys SET revoked_at=? WHERE key_id=? AND revoked_at IS NULL',(now,key_id))
            if cur.rowcount!=1: raise ApprovalError('KEY_NOT_ACTIVE')

    def set_reviewer(self, reviewer, role, *, active, directory_version):
        _id(reviewer); _id(directory_version)
        if role not in ROLES or type(active) is not bool: raise ApprovalError('INVALID_DIRECTORY_ROLE')
        with self.db:
            self.db.execute('INSERT INTO reviewer_directory VALUES (?,?,?,?) ON CONFLICT(reviewer) DO UPDATE SET role=excluded.role,active=excluded.active,directory_version=excluded.directory_version',
                            (reviewer,role,int(active),directory_version))

    def record_policy_attested(self, migration_id, bundle, assertion, *, key_id, directory_version, now):
        _id(key_id); _id(directory_version)
        if type(now) is not int or now<0 or not isinstance(assertion,dict): raise ApprovalError('INVALID_ASSERTION')
        reviewer=_id(assertion.get('reviewer'))
        role=assertion.get('role')
        if role not in ROLES: raise ApprovalError('INVALID_ROLE')
        # Serialize key checks and reviewer policy against concurrent revocation.
        try:
            self.db.execute('BEGIN IMMEDIATE')
            key=self.db.execute('SELECT secret,valid_from,valid_until,revoked_at FROM issuer_keys WHERE key_id=?',(key_id,)).fetchone()
            if key is None or not key[1]<=now<key[2] or (key[3] is not None and now>=key[3]):
                raise ApprovalError('ISSUER_KEY_INACTIVE')
            identity=self.db.execute('SELECT role,active,directory_version FROM reviewer_directory WHERE reviewer=?',(reviewer,)).fetchone()
            if identity!=(role,1,directory_version): raise ApprovalError('REVIEWER_NOT_AUTHORIZED')
            # Validate signature and assertion while holding the SAME SQLite write lock.
            # Reuse the base validator without allowing it to open a second transaction.
            from authenticated_review_ledger import IDENT as ASSERT_IDENT
            import re as _re
            required={'migration_id','evidence_hash','role','reviewer','nonce','issued_at','expires_at','signature'}
            if set(assertion)!=required: raise ApprovalError('INVALID_ASSERTION_FIELDS')
            fields={k:assertion[k] for k in required-{'signature'}}
            for name in ('migration_id','role','reviewer','nonce'):
                if not isinstance(fields[name],str) or not ASSERT_IDENT.fullmatch(fields[name]):
                    raise ApprovalError('INVALID_ASSERTION_ID')
            if fields['role'] not in ROLES: raise ApprovalError('INVALID_ROLE')
            if not isinstance(fields['evidence_hash'],str) or not _re.fullmatch('[0-9a-f]{64}',fields['evidence_hash']):
                raise ApprovalError('INVALID_ASSERTION_HASH')
            if (type(fields['issued_at']) is not int or type(fields['expires_at']) is not int
                or fields['issued_at']<0 or fields['issued_at']>now
                or fields['expires_at']<=now or fields['expires_at']-fields['issued_at']>3600):
                raise ApprovalError('EXPIRED_OR_INVALID_ASSERTION')
            expected=hmac.new(key[0],_payload(fields),hashlib.sha256).hexdigest()
            if not isinstance(assertion['signature'],str) or not hmac.compare_digest(assertion['signature'],expected):
                raise ApprovalError('BAD_ASSERTION_SIGNATURE')
            evidence=self._evidence(migration_id,bundle)
            if fields['migration_id']!=migration_id or fields['evidence_hash']!=evidence:
                raise ApprovalError('ASSERTION_EVIDENCE_MISMATCH')
            self._record_verified_in_transaction(migration_id,evidence,fields,now)
            self.db.execute('COMMIT')
            return {'status':'ATTESTED_REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED',
                    'cutover_authorized':False,'production_qualified':False}
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
