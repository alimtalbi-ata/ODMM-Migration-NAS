"""Fail-closed local lab review policy; identities must be verified externally.

No authentication, network operations or NAS execution. Author: Abdelhalim Talbi.
"""
from odmm_linux_datamover_intents import _id

class PolicyDenied(PermissionError):
    pass

ROLE_DECISIONS = {
    "observer": frozenset(),
    "reviewer": frozenset(("HOLD", "REQUEST_RECHECK")),
    "incident_lead": frozenset(("HOLD", "REQUEST_RECHECK", "ESCALATE")),
}

def authorize_review(*, operator_id, role, decision, identity_verified=False):
    operator_id = _id(operator_id)
    if identity_verified is not True:
        raise PolicyDenied("IDENTITY_NOT_VERIFIED")
    if role not in ROLE_DECISIONS:
        raise PolicyDenied("UNKNOWN_ROLE")
    if decision not in ROLE_DECISIONS[role]:
        raise PolicyDenied("DECISION_NOT_AUTHORIZED")
    return {"operator_id": operator_id, "role": role, "decision": decision,
            "authorizes_resume": False}
