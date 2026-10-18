"""Fail-closed deployment gate for review writes. Author: Abdelhalim Talbi."""
from fastapi import HTTPException
from qualification_review_security_v2217 import verify_anchor


def enforce_review_gate(identity, *, review_db_path, anchor_path, secret, required_role='qualification:approve', forbidden_role='qualification:prepare'):
    """Requires independent pre-existing anchor and separation of duties.

    No cutover capability is conferred. Caller must authenticate identity with an IdP.
    """
    if not isinstance(identity, dict) or not isinstance(identity.get('subject'), str) or not identity['subject'].strip():
        raise HTTPException(403, 'AUTHENTICATION_REQUIRED')
    roles = identity.get('roles')
    if not isinstance(roles, (list, tuple, set)) or required_role not in roles or forbidden_role in roles:
        raise HTTPException(403, 'SEPARATION_OF_DUTIES_REQUIRED')
    if not anchor_path:
        raise HTTPException(503, 'INDEPENDENT_ANCHOR_REQUIRED')
    try:
        verify_anchor(review_db_path, anchor_path, secret)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(503, 'REVIEW_ANCHOR_UNVERIFIED') from exc
    return identity['subject'].strip()
