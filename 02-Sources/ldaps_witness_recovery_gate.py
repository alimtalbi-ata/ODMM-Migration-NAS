"""V188.0: read-only, fail-closed recovery qualification for an independent witness.

Never performs repair, replay, publication, migration, or cutover. The operator
must provide a freshly verified local checkpoint; stale checkpoints are refused.
"""
import hashlib
import hmac
import json
import time
from ldaps_ipc_persistent_identity import IdentityPinError


def _hexmac(v):
    return isinstance(v, str) and len(v) == 64 and all(c in '0123456789abcdef' for c in v)


class WitnessRecoveryGate:
    def __init__(self, *, verifier, local_anchor, clock=None):
        self.verifier = verifier
        self.local_anchor = local_anchor
        self.clock = clock or time.time

    def assess(self, *, expected_count, expected_last_mac, incident_id, operator_acknowledged=False):
        """Check independently stored remote head against verified local anchor.

        Returns a non-authorizing evidence report. Failures propagate fail-closed.
        """
        if (type(expected_count) is not int or expected_count < 0 or
            not _hexmac(expected_last_mac) or not isinstance(incident_id, str) or
            not 1 <= len(incident_id) <= 128 or any(ord(c) < 32 for c in incident_id)):
            raise IdentityPinError('WITNESS_RECOVERY_INPUT_INVALID')
        if operator_acknowledged is not True:
            raise IdentityPinError('WITNESS_RECOVERY_OPERATOR_ACK_REQUIRED')
        # local verify checks both anchor HMAC and the durable review ledger.
        self.local_anchor.verify()
        state = self.local_anchor._read()
        # Do not trust a successful local check if it refers to a different head.
        if state.get('count') != expected_count or state.get('last_mac') != expected_last_mac:
            raise IdentityPinError('WITNESS_RECOVERY_LOCAL_STATE_CHANGED')
        remote = self.verifier.verify(expected_count=expected_count, expected_last_mac=expected_last_mac)
        if remote.get('status') != 'REMOTE_WITNESS_VERIFIED' or remote.get('count') != expected_count:
            raise IdentityPinError('WITNESS_RECOVERY_REMOTE_UNVERIFIED')
        return {'status':'WITNESS_RECOVERY_EVIDENCE_MATCH', 'incident_id':incident_id,
                'count':expected_count,'last_mac':expected_last_mac,
                'checked_at_unix':int(self.clock()), 'operator_acknowledged':True,
                'recovery_authorized':False,'cutover_authorized':False,
                'publication_authorized':False,'manual_reconciliation_required':True}

    def retry_assess(self, *, attempts=2, delay=None, **kwargs):
        """Bounded recheck after transient outage; never bypasses divergence.

        Explicitly opt-in; defaults to no sleeping, and only retries transport
        unavailability. All other errors are terminal.
        """
        if type(attempts) is not int or not 1 <= attempts <= 3:
            raise IdentityPinError('WITNESS_RECOVERY_RETRY_INVALID')
        for n in range(attempts):
            try:
                return self.assess(**kwargs)
            except IdentityPinError as exc:
                if str(exc) != 'REMOTE_WITNESS_UNAVAILABLE' or n == attempts - 1:
                    raise
                if delay is not None:
                    delay(n + 1)
