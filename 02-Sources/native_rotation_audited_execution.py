"""V195.4: fail-closed audited admission, with explicit ambiguous-outcome recovery.

This is not a distributed transaction with the external rotation effect. An
interruption after admission MUST be reconciled by an operator, never replayed.
"""
import hashlib
import re
from native_rotation_access_audit import canonical

_ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')


def _existing(audit, event_id):
    for event in audit.export_verified()['events']:
        if event['event_id'] == event_id:
            return event
    return None


def execute_audited_rotation(*, audit, request_id, subject, target_key_id,
                             authorize, execute):
    """Persist admission BEFORE effect; never repeat admitted operation.

    authorize() must validate OIDC, RBAC and signed approval independently.
    execute() is the sealed governance entrypoint. It must itself be idempotent.
    """
    if any(not isinstance(v,str) or not _ID.fullmatch(v)
           for v in (request_id, subject, target_key_id)):
        raise ValueError('AUDITED_ROTATION_ID_INVALID')
    if not callable(authorize) or not callable(execute):
        raise ValueError('AUDITED_ROTATION_PROVIDERS_REQUIRED')
    # Avoid collisions between distinct subjects/targets for same request ID.
    fingerprint = hashlib.sha256(canonical({'request_id':request_id,
                   'subject':subject,'target_key_id':target_key_id})).hexdigest()
    admission_id = 'admit:'+request_id
    existing = _existing(audit, admission_id)
    if existing is not None:
        if existing.get('fingerprint') != fingerprint:
            raise ValueError('AUDITED_ROTATION_REQUEST_CONFLICT')
        raise ValueError('AUDITED_ROTATION_ALREADY_ADMITTED_RECONCILE')
    # No effect is possible if authorization or audit is unavailable.
    if authorize() is not True:
        audit.append({'event_id':'deny:'+request_id,'event':'rotation_access_denied',
                      'subject':subject,'request_id':request_id,'reason':'AUTHORIZATION_DENIED',
                      'fingerprint':fingerprint})
        raise ValueError('AUDITED_ROTATION_NOT_AUTHORIZED')
    audit.append({'event_id':admission_id,'event':'rotation_access_allowed',
                  'subject':subject,'request_id':request_id,'fingerprint':fingerprint,
                  'target_key_id':target_key_id,'phase':'ADMITTED_PENDING_EFFECT'})
    try:
        result = execute()
    except BaseException:
        # Do not blindly retry: effect might have committed before error.
        try:
            audit.append({'event_id':'uncertain:'+request_id,
                          'event':'rotation_access_denied','request_id':request_id,
                          'reason':'EFFECT_OUTCOME_UNCERTAIN','fingerprint':fingerprint})
        except BaseException:
            pass
        raise
    # Failure to persist outcome also leaves request permanently blocked.
    audit.append({'event_id':'complete:'+request_id,'event':'rotation_access_allowed',
                  'request_id':request_id,'fingerprint':fingerprint,
                  'phase':'EFFECT_RETURNED'})
    return result
