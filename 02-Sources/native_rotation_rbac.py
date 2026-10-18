"""V195.1: server-side RBAC policy for the guarded rotation endpoint.

The identity provider MUST validate the session/token independently. Neither HTTP
headers nor JSON claims are interpreted as proof of authentication here.
"""
import re
from native_rotation_target_binding import _validate as validate_signed_target

_SUBJECT = re.compile(r'[A-Za-z0-9_.@-]{1,128}\Z')


def build_rotation_authorization(*, identity_provider, gateway_key_provider,
                                 denial_audit, required_role='rotation_executor', clock_ns=None):
    """Return authorization(request, body) callback for V195.1 portal binding.

    identity_provider(request) -> {authenticated: True, subject: str, roles: iterable}
    gateway_key_provider() -> independently protected signing key
    denial_audit(record) -> durable, externally monitored audit sink (must succeed)
    """
    if not all(callable(x) for x in (identity_provider,gateway_key_provider,denial_audit)):
        raise ValueError('RBAC_PROVIDERS_REQUIRED')
    if not isinstance(required_role,str) or not required_role:
        raise ValueError('RBAC_ROLE_INVALID')

    def authorize(request, body):
        import time
        reason='IDENTITY_INVALID'; subject=None
        rid=body.get('request_id') if isinstance(body,dict) else None
        request_id=rid if isinstance(rid,str) and len(rid)<=128 else None
        try:
            identity=identity_provider(request)
            if not isinstance(identity,dict) or identity.get('authenticated') is not True:
                reason='UNAUTHENTICATED'
            else:
                subject=identity.get('subject')
                if not isinstance(subject,str) or not _SUBJECT.fullmatch(subject):
                    reason='IDENTITY_INVALID'
                else:
                    roles=identity.get('roles')
                    if not isinstance(roles,(list,tuple,frozenset,set)) or any(not isinstance(r,str) for r in roles):
                        reason='ROLES_INVALID'
                    elif required_role not in roles:
                        reason='ROLE_DENIED'
                    elif not isinstance(body,dict) or set(body)!={'request_id','target_key_id','signed_target'}:
                        reason='PAYLOAD_INVALID'
                    else:
                        key=gateway_key_provider()
                        now=time.time_ns() if clock_ns is None else clock_ns()
                        approval=validate_signed_target(body['signed_target'],key,now)
                        if body['request_id']!=approval['request_id'] or body['target_key_id']!=approval['target_key_id']:
                            reason='APPROVAL_MISMATCH'
                        elif subject in (approval['requester'],approval['reviewer']):
                            reason='SEPARATION_OF_DUTIES'
                        else:
                            return True
        except Exception:
            reason='VERIFICATION_ERROR'
        # The audit sink is mandatory; failures propagate and block execution.
        denial_audit({'event':'rotation_access_denied','reason':reason,
                      'subject':subject,'request_id':request_id})
        return False
    authorize._odmm_body_aware = True
    return authorize
