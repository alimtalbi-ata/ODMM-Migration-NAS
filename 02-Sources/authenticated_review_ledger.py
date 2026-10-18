"""HMAC-attested reviewer assertions, atomic nonce consumption and audit.
Requires a trusted external issuer; HMAC is not AD/LDAP login or PKI identity.
"""
import hashlib
import hmac
import json
import re
from atomic_review_ledger import AtomicReviewLedger
from human_approval_registry import ApprovalError
from dual_review_ledger import ROLES

IDENT = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')

def _payload(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def sign_assertion(secret, *, migration_id, evidence_hash, role, reviewer, nonce, issued_at, expires_at):
    """For trusted issuer / test fixtures ONLY; never expose issuer secret to reviewers."""
    fields = dict(migration_id=migration_id, evidence_hash=evidence_hash, role=role,
                  reviewer=reviewer, nonce=nonce, issued_at=issued_at, expires_at=expires_at)
    return dict(fields, signature=hmac.new(secret, _payload(fields), hashlib.sha256).hexdigest())

class AuthenticatedReviewLedger(AtomicReviewLedger):
    def __init__(self, path, *, issuer_secret):
        if not isinstance(issuer_secret, bytes) or len(issuer_secret) < 32:
            raise ApprovalError('INVALID_ISSUER_KEY')
        super().__init__(path)
        self._issuer_secret = issuer_secret
        self.db.execute('CREATE TABLE IF NOT EXISTS consumed_review_nonces (nonce TEXT PRIMARY KEY, migration_id TEXT NOT NULL, reviewer TEXT NOT NULL)')

    def _record_verified_in_transaction(self, migration_id, evidence, fields, now):
            if self.verify_journal()['status'] != 'CHAIN_INTACT_UNAUTHENTICATED':
                raise ApprovalError('AUDIT_CHAIN_INVALID')
            other=self.db.execute('SELECT reviewer,evidence_hash FROM dual_reviews WHERE migration_id=?',(migration_id,)).fetchall()
            if any(r[0] == fields['reviewer'] for r in other): raise ApprovalError('SEPARATION_OF_DUTIES')
            if any(r[1] != evidence for r in other): raise ApprovalError('STALE_EVIDENCE')
            self.db.execute('INSERT INTO consumed_review_nonces VALUES (?,?,?)',
                            (fields['nonce'],migration_id,fields['reviewer']))
            self.db.execute('INSERT INTO dual_reviews VALUES (?,?,?,?,?,NULL,?)',
                            (migration_id,fields['role'],fields['reviewer'],evidence,fields['expires_at'],now))
            self._append_in_transaction(migration_id,'REVIEW_RECORDED',fields['reviewer'],evidence,now)

    def record_attested(self, migration_id, bundle, assertion, *, now):
        if type(now) is not int or now < 0 or not isinstance(assertion, dict):
            raise ApprovalError('INVALID_ASSERTION')
        keys = {'migration_id','evidence_hash','role','reviewer','nonce','issued_at','expires_at','signature'}
        if set(assertion) != keys: raise ApprovalError('INVALID_ASSERTION_FIELDS')
        fields = {k:assertion[k] for k in keys - {'signature'}}
        for key in ('migration_id','role','reviewer','nonce'):
            if not isinstance(fields[key], str) or not IDENT.fullmatch(fields[key]):
                raise ApprovalError('INVALID_ASSERTION_ID')
        if fields['role'] not in ROLES: raise ApprovalError('INVALID_ROLE')
        if not isinstance(fields['evidence_hash'],str) or not re.fullmatch('[0-9a-f]{64}',fields['evidence_hash']):
            raise ApprovalError('INVALID_ASSERTION_HASH')
        if (type(fields['issued_at']) is not int or type(fields['expires_at']) is not int
            or fields['issued_at'] < 0 or fields['issued_at'] > now
            or fields['expires_at'] <= now or fields['expires_at'] - fields['issued_at'] > 3600):
            raise ApprovalError('EXPIRED_OR_INVALID_ASSERTION')
        signature = assertion['signature']
        expected = hmac.new(self._issuer_secret, _payload(fields), hashlib.sha256).hexdigest()
        if not isinstance(signature,str) or not hmac.compare_digest(signature,expected):
            raise ApprovalError('BAD_ASSERTION_SIGNATURE')
        evidence = self._evidence(migration_id,bundle)
        if fields['migration_id'] != migration_id or fields['evidence_hash'] != evidence:
            raise ApprovalError('ASSERTION_EVIDENCE_MISMATCH')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self._record_verified_in_transaction(migration_id, evidence, fields, now)
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        return {'status':'ATTESTED_REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED',
                'cutover_authorized':False, 'production_qualified':False}
