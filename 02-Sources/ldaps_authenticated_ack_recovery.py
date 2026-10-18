"""Authenticated, role-separated manual acknowledgement recovery.

HMAC identities are issued by a trusted *external* issuer; this is not AD login.
Keys must be provisioned out-of-band. No migration/cutover side effects.
"""
import hashlib
import hmac
import json
from ldaps_ack_recovery import InterruptedAckRecovery
from ldaps_transition_reconciliation import TransitionReconciliationError

class AuthenticatedAckRecovery:
    def __init__(self, recovery, *, issuer_keys, grants):
        if not isinstance(recovery, InterruptedAckRecovery):
            raise TransitionReconciliationError('INVALID_RECOVERY')
        if not isinstance(issuer_keys, dict) or not issuer_keys or any(not isinstance(k,str) or not isinstance(v,bytes) or len(v)<32 for k,v in issuer_keys.items()):
            raise TransitionReconciliationError('INVALID_ISSUER_KEYS')
        self.recovery=recovery
        self.keys=dict(issuer_keys)
        self.grants=dict(grants)
        self.db=recovery.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS authenticated_ack_reviews (
          seq INTEGER PRIMARY KEY, intent_hash TEXT NOT NULL UNIQUE,
          reviewer TEXT NOT NULL, operator TEXT NOT NULL, token_id TEXT NOT NULL UNIQUE,
          reviewed_at INTEGER NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    @staticmethod
    def sign(key, *, issuer, subject, role, token_id, issued_at, expires_at):
        claims={'issuer':issuer,'subject':subject,'role':role,'token_id':token_id,
                'issued_at':issued_at,'expires_at':expires_at}
        payload=json.dumps(claims,sort_keys=True,separators=(',',':')).encode()
        return {**claims,'signature':hmac.new(key,payload,hashlib.sha256).hexdigest()}

    def _authenticate(self, token, now):
        if not isinstance(token,dict) or set(token)!={'issuer','subject','role','token_id','issued_at','expires_at','signature'}:
            raise TransitionReconciliationError('INVALID_IDENTITY_TOKEN')
        issuer=token['issuer']; subject=token['subject']; role=token['role']; token_id=token['token_id']
        if not all(isinstance(x,str) and x.strip() and len(x)<=128 for x in (issuer,subject,role,token_id)):
            raise TransitionReconciliationError('INVALID_IDENTITY_TOKEN')
        if type(now)!=int or now<0 or type(token['issued_at'])!=int or type(token['expires_at'])!=int or not token['issued_at']<=now<token['expires_at']:
            raise TransitionReconciliationError('EXPIRED_IDENTITY_TOKEN')
        key=self.keys.get(issuer)
        if key is None or not isinstance(token['signature'],str):
            raise TransitionReconciliationError('UNTRUSTED_IDENTITY_ISSUER')
        claims={k:token[k] for k in token if k!='signature'}
        expected=hmac.new(key,json.dumps(claims,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,token['signature']):
            raise TransitionReconciliationError('INVALID_IDENTITY_SIGNATURE')
        if self.grants.get(subject)!=role or role!='SECURITY':
            raise TransitionReconciliationError('RECOVERY_SECURITY_ROLE_REQUIRED')
        return subject,token_id

    @staticmethod
    def _hash(row):
        return hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def _verify_rows(self):
        rows=self.db.execute('SELECT seq,intent_hash,reviewer,operator,token_id,reviewed_at,previous_hash,event_hash FROM authenticated_ack_reviews ORDER BY seq').fetchall()
        prev='0'*64
        for n,(seq,ih,reviewer,operator,tid,at,old,digest) in enumerate(rows,1):
            item={'seq':seq,'intent_hash':ih,'reviewer':reviewer,'operator':operator,'token_id':tid,'reviewed_at':at,'previous_hash':prev}
            if seq!=n or old!=prev or not hmac.compare_digest(self._hash(item),digest):
                raise TransitionReconciliationError('AUTHENTICATED_REVIEW_AUDIT_TAMPERED')
            prev=digest
        return rows

    def verify(self):
        self.recovery.verify()
        return {'valid':True,'count':len(self._verify_rows())}

    def recover(self, *, token, original_operator, operator_confirmed, now, max_age_seconds):
        reviewer,tid=self._authenticate(token,now)
        if reviewer==original_operator:
            raise TransitionReconciliationError('INDEPENDENT_REVIEWER_REQUIRED')
        if operator_confirmed is not True:
            raise TransitionReconciliationError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        # Serialized across cooperating administrators; a durable authenticated
        # review record is written before attempting filesystem unlink.
        if True:  # the underlying recovery APIs acquire their own non-reentrant file lock
            self._verify_rows()
            status=self.recovery.inspect()
            if status['status']!='RECOVERABLE_WITH_INDEPENDENT_REVIEW':
                raise TransitionReconciliationError('RECOVERY_NOT_READY')
            ih=status['intent_hash']
            if now<status['acknowledged_at'] or now-status['acknowledged_at']>max_age_seconds:
                raise TransitionReconciliationError('STALE_RECEIPT')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                rows=self._verify_rows()
                if any(r[1]==ih or r[4]==tid for r in rows):
                    raise TransitionReconciliationError('AUTHENTICATED_REVIEW_REPLAY')
                seq=len(rows)+1;prev=rows[-1][7] if rows else '0'*64
                item={'seq':seq,'intent_hash':ih,'reviewer':reviewer,'operator':original_operator,
                      'token_id':tid,'reviewed_at':now,'previous_hash':prev}
                digest=self._hash(item)
                self.db.execute('INSERT INTO authenticated_ack_reviews VALUES (?,?,?,?,?,?,?,?)',
                                (seq,ih,reviewer,original_operator,tid,now,prev,digest))
                self.db.commit()
            except BaseException:
                self.db.rollback();raise
            # Crash after this commit is fail-closed: no automatic replay.
            result=self.recovery.recover(reviewer=reviewer,original_operator=original_operator,
                         operator_confirmed=True,now=now,max_age_seconds=max_age_seconds)
            return {**result,'authenticated_review_hash':digest,'execution_authorized':False,'cutover_authorized':False}
