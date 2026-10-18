"""Fail-closed anchor refresh after review writes (single-process coordination).
Author: Abdelhalim Talbi.
"""
from threading import RLock
from fastapi import HTTPException
from qualification_review_gate_v2218 import enforce_review_gate
from qualification_review_security_v2217 import write_anchor, verify_anchor
from qualification_decisions_v2215 import append_review

_LOCK = RLock()

def append_review_with_anchor(db_path, anchor_path, dossier, *, identity, action, reason, secret):
    """Precheck anchor, append decision, refresh and verify anchor under process lock.

    Cross-process writers require a distributed lock. An anchor write failure leaves
    a committed review event and a stale anchor: subsequent writes fail closed.
    """
    with _LOCK:
        reviewer = enforce_review_gate(identity, review_db_path=db_path,
                                       anchor_path=anchor_path, secret=secret)
        event = append_review(db_path, dossier, action=action, reviewer=reviewer,
                              reason=reason, secret=secret)
        try:
            write_anchor(db_path, anchor_path, secret)
            verify_anchor(db_path, anchor_path, secret)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise HTTPException(503, 'REVIEW_COMMITTED_ANCHOR_REFRESH_FAILED') from exc
        return event
