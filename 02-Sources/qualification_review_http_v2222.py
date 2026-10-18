"""V222.2: HTTP idempotency adapter for the existing review portal. Author: Abdelhalim Talbi."""
from fastapi import HTTPException
from qualification_review_coordination_v2220 import append_review_coordinated
from qualification_decisions_v2215 import append_review


def parse_request_id(request):
    """Require stable client-provided key; never generate a new key per retry."""
    value = request.headers.get('Idempotency-Key')
    if not isinstance(value, str) or not 8 <= len(value) <= 128 or not all(c.isascii() and (c.isalnum() or c in '-_') for c in value):
        raise HTTPException(400, 'INVALID_IDEMPOTENCY_KEY')
    return value


def append_http_review(db_path, anchor_path, dossier, *, identity, action, reason, secret, request_id, strict):
    if strict:
        return append_review_coordinated(db_path, anchor_path, dossier, identity=identity,
                                         action=action, reason=reason, secret=secret, request_id=request_id)
    return append_review(db_path, dossier, action=action, reviewer=identity['subject'].strip(),
                         reason=reason, secret=secret, request_id=request_id)
