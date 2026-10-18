"""V187.0: authenticated, non-destructive review of interrupted IPC rotations.

This is an evidence receipt, NOT a repair mechanism. The original mismatch remains
blocked. Requires the same cooperative interprocess lock as rotation.
"""
import hashlib
import hmac
import json
from ldaps_ipc_persistent_identity import IdentityPinError


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


class SupervisedRotationReconciliation:
    def __init__(self, serialized, *, receipt_key):
        if not isinstance(receipt_key, bytes) or len(receipt_key) < 32:
            raise IdentityPinError('RECONCILIATION_KEY_TOO_SHORT')
        self.serialized = serialized
        self.key = receipt_key

    def _snapshot(self):
        facade = self.serialized.facade
        # Collect evidence under the cooperative lock; never mutate the pin or checkpoint.
        status = facade.inspect()['status']
        audit = facade.controller.verify_audit()['last_mac']
        pin = facade.controller.pin._read()
        pin_mac = facade.controller.pin._mac(pin) if pin is not None else None
        checkpoint = facade._checkpoint()
        return {'version': 1, 'status': status, 'audit_mac': audit,
                'pin_mac': pin_mac, 'checkpoint_mac': facade._mac(checkpoint) if checkpoint is not None else None}

    def report(self):
        def action():
            snapshot = self._snapshot()
            digest = hashlib.sha256(canonical(snapshot)).hexdigest()
            return {'status': snapshot['status'], 'evidence_sha256': digest,
                    'manual_review_required': snapshot['status'] != 'CHECKPOINT_VERIFIED',
                    'execution_authorized': False, 'cutover_authorized': False,
                    'automatic_repair_authorized': False}
        return self.serialized._locked(action)

    def review(self, *, security_token, operations_token, now, expected_evidence_sha256, operator_confirmed):
        return self.serialized._locked(lambda: self._review_locked(security_token=security_token, operations_token=operations_token, now=now, expected_evidence_sha256=expected_evidence_sha256, operator_confirmed=operator_confirmed))

    def _review_locked(self, *, security_token, operations_token, now, expected_evidence_sha256, operator_confirmed):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if type(now) is not int or now < 0:
            raise IdentityPinError('INVALID_TIME')
        verifier = self.serialized.facade.verifier
        sec = verifier.verify(security_token, now=now)
        ops = verifier.verify(operations_token, now=now)
        if (sec['subject'] == ops['subject'] or sec['token_id'] == ops['token_id']
                or sec['issuer'] != ops['issuer']):
            raise IdentityPinError('REVIEWER_SEPARATION_REQUIRED')
        if not hasattr(verifier, 'assert_role'):
            raise IdentityPinError('ROLE_AUTHORITY_REQUIRED')
        verifier.assert_role(sec, 'SECURITY')
        verifier.assert_role(ops, 'OPERATIONS')
        if not isinstance(expected_evidence_sha256, str) or len(expected_evidence_sha256) != 64:
            raise IdentityPinError('EVIDENCE_DIGEST_INVALID')

        def action():
            snapshot = self._snapshot()
            digest = hashlib.sha256(canonical(snapshot)).hexdigest()
            if not hmac.compare_digest(digest, expected_evidence_sha256):
                raise IdentityPinError('EVIDENCE_CHANGED_MANUAL_REVIEW')
            if snapshot['status'] == 'CHECKPOINT_VERIFIED':
                raise IdentityPinError('NO_INTERRUPTED_ROTATION')
            # Receipt is signed and returned, not persisted: callers must archive it
            # in a separately controlled evidence store. It cannot authorize recovery.
            record = {'version': 1, 'evidence_sha256': digest, 'reviewed_at': now,
                      'security_subject': sec['subject'], 'operations_subject': ops['subject'],
                      'security_token_id': sec['token_id'], 'operations_token_id': ops['token_id'],
                      'decision': 'MANUAL_INVESTIGATION_REQUIRED'}
            mac = hmac.new(self.key, canonical(record), hashlib.sha256).hexdigest()
            return {'status': 'REVIEW_RECEIPT_ISSUED', 'receipt': record, 'hmac_sha256': mac,
                    'automatic_repair_authorized': False, 'execution_authorized': False,
                    'cutover_authorized': False}
        return action()

    def verify_receipt(self, receipt):
        if not isinstance(receipt, dict) or set(receipt) != {'receipt', 'hmac_sha256', 'status',
                'automatic_repair_authorized', 'execution_authorized', 'cutover_authorized'}:
            raise IdentityPinError('REVIEW_RECEIPT_INVALID')
        mac = hmac.new(self.key, canonical(receipt['receipt']), hashlib.sha256).hexdigest()
        if not isinstance(receipt['hmac_sha256'], str) or not hmac.compare_digest(mac, receipt['hmac_sha256']):
            raise IdentityPinError('REVIEW_RECEIPT_INVALID')
        if receipt['receipt'].get('decision') != 'MANUAL_INVESTIGATION_REQUIRED':
            raise IdentityPinError('REVIEW_RECEIPT_INVALID')
        return {'status': 'RECEIPT_SIGNATURE_VERIFIED', 'recovery_authorized': False,
                'cutover_authorized': False}
