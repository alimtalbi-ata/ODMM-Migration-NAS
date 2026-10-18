"""V195.7: read-only external equipment evidence adapter, fail closed.

The verifier callback is supplied by deployment, not by a request body. It
must perform independent read-only observation; this module cannot prove that.
"""
import hashlib
import re
from native_rotation_access_audit import canonical
from native_rotation_reconciliation import inspect_rotation_outcome
from native_rotation_evidence import record_verification

_ASSET = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")

def verify_external_state(*, audit, request_id, verifier, asset_id,
                          expected_state, observer, verify_identity):
    """Observe equipment once, record a digest, never retry any effect.

    observer(asset_id) must return a dict with `asset_id`, `state`, `source`,
    `observed_at` and `evidence`; no arbitrary network action is done here.
    """
    if not isinstance(asset_id,str) or not _ASSET.fullmatch(asset_id):
        raise ValueError('EXTERNAL_ASSET_INVALID')
    if not isinstance(expected_state,str) or not expected_state or len(expected_state)>256:
        raise ValueError('EXTERNAL_EXPECTATION_INVALID')
    if not callable(observer) or not callable(verify_identity):
        raise ValueError('EXTERNAL_TRUSTED_PROVIDERS_REQUIRED')
    if verify_identity(verifier,request_id) is not True:
        raise ValueError('EXTERNAL_VERIFIER_UNAUTHORIZED')
    outcome=inspect_rotation_outcome(audit=audit,request_id=request_id)
    if outcome['state']=='NOT_ADMITTED':
        raise ValueError('EXTERNAL_NOT_ADMITTED')
    # No side effects until eligibility and verifier authorization are checked.
    observation=observer(asset_id)
    if not isinstance(observation,dict) or set(observation)!={'asset_id','state','source','observed_at','evidence'}:
        raise ValueError('EXTERNAL_OBSERVATION_INVALID')
    if observation['asset_id']!=asset_id or not isinstance(observation['state'],str) or not observation['state']:
        raise ValueError('EXTERNAL_OBSERVATION_ASSET_MISMATCH')
    if not isinstance(observation['source'],str) or not observation['source'] or not isinstance(observation['observed_at'],str) or not observation['observed_at']:
        raise ValueError('EXTERNAL_OBSERVATION_PROVENANCE_REQUIRED')
    if not isinstance(observation['evidence'],dict) or len(canonical(observation))>65536:
        raise ValueError('EXTERNAL_OBSERVATION_SIZE_INVALID')
    finding='MATCHES_EXPECTED' if observation['state']==expected_state else 'DIFFERS_FROM_EXPECTED'
    digest=hashlib.sha256(canonical({'request_id':request_id,'asset_id':asset_id,'expected_state':expected_state,'observation':observation})).hexdigest()
    result=record_verification(audit=audit,request_id=request_id,verifier=verifier,
        observation=finding,evidence_digest=digest,verify_identity=verify_identity)
    return {**result,'asset_id':asset_id,'evidence_digest':digest,'source':observation['source'],
            'equipment_state_verified_by_deployment':False,'retry_allowed':False}
