"""V195.6: append-only human verification evidence, never triggers a retry."""
import hashlib
from native_rotation_access_audit import canonical
from native_rotation_reconciliation import inspect_rotation_outcome

VALID = frozenset({'MATCHES_EXPECTED', 'DIFFERS_FROM_EXPECTED', 'INCONCLUSIVE'})

def record_verification(*, audit, request_id, verifier, observation, evidence_digest, verify_identity):
    """Store an attested observation; verifier identity is checked by trusted deployment callback.

    A positive observation does not prove external state without a trustworthy
    independent verification provider; this function never calls equipment.
    """
    if not isinstance(verifier, str) or not verifier or len(verifier)>128:
        raise ValueError('VERIFICATION_IDENTITY_INVALID')
    if observation not in VALID:
        raise ValueError('VERIFICATION_OBSERVATION_INVALID')
    if not isinstance(evidence_digest,str) or len(evidence_digest)!=64 or any(c not in '0123456789abcdef' for c in evidence_digest):
        raise ValueError('VERIFICATION_DIGEST_INVALID')
    if not callable(verify_identity) or verify_identity(verifier,request_id) is not True:
        raise ValueError('VERIFICATION_NOT_AUTHORIZED')
    status=inspect_rotation_outcome(audit=audit,request_id=request_id)
    if status['state']=='NOT_ADMITTED':
        raise ValueError('VERIFICATION_NOT_ADMITTED')
    event={'event_id':'verify:'+request_id,'event':'rotation_access_allowed',
           'request_id':request_id,'verifier':verifier,'observation':observation,
           'evidence_digest':evidence_digest,'phase':'INDEPENDENT_OBSERVATION'}
    result=audit.append(event)
    if result['duplicate']:
        raise ValueError('VERIFICATION_ALREADY_RECORDED')
    return {'request_id':request_id,'observation':observation,'audit_head':result['head'],
            'retry_allowed':False,'externally_qualified':False}
