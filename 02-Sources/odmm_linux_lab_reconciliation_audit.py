"""Append-only operator review journal; never authorizes NAS effects.

Local SQLite laboratory control plane only. Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import sqlite3
import time
from odmm_linux_datamover_intents import _id, _transaction

class ReviewConflict(RuntimeError):
    pass

DECISIONS = frozenset(("HOLD", "REQUEST_RECHECK", "ESCALATE"))

def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS odmm_reconciliation_reviews (
        review_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL, operator_id TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('HOLD','REQUEST_RECHECK','ESCALATE')),
        evidence_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    db.commit()

def record_review(db, *, review_id, intent_id, operator_id, decision, evidence, role=None, identity_verified=False, now=None):
    from odmm_linux_lab_review_policy import authorize_review
    authorize_review(operator_id=operator_id, role=role, decision=decision, identity_verified=identity_verified)
    review_id, intent_id, operator_id = _id(review_id), _id(intent_id), _id(operator_id)
    if decision not in DECISIONS:
        raise ValueError("INVALID_REVIEW_DECISION")
    if not isinstance(evidence, dict) or evidence.get("intent_id") != intent_id or evidence.get("state") != "UNCERTAIN" or evidence.get("decision") != "MANUAL_REVIEW_REQUIRED":
        raise ValueError("INVALID_RECONCILIATION_EVIDENCE")
    try:
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("INVALID_RECONCILIATION_EVIDENCE") from exc
    digest = hashlib.sha256(canonical).hexdigest()
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("INVALID_TIME")
    def work():
        row = db.execute("SELECT state FROM odmm_datamover_intents WHERE intent_id=?", (intent_id,)).fetchone()
        if not row or row[0] != "UNCERTAIN":
            raise ReviewConflict("INTENT_NOT_UNCERTAIN")
        try:
            db.execute("""INSERT INTO odmm_reconciliation_reviews
                (review_id,intent_id,operator_id,decision,evidence_sha256,created_at)
                VALUES (?,?,?,?,?,?)""",
                (review_id,intent_id,operator_id,decision,digest,now))
        except sqlite3.IntegrityError as exc:
            raise ReviewConflict("DUPLICATE_REVIEW_ID") from exc
        return {"review_id": review_id, "intent_id": intent_id,
                "decision": decision, "evidence_sha256": digest,
                "state_after": "UNCERTAIN"}
    return _transaction(db, work)

def verify_review(db, review_id, evidence):
    """Verify a stored SHA256 evidence fingerprint; no authorization is granted."""
    review_id = _id(review_id)
    row = db.execute("""SELECT intent_id,operator_id,decision,evidence_sha256,created_at
        FROM odmm_reconciliation_reviews WHERE review_id=?""", (review_id,)).fetchone()
    if row is None:
        raise ReviewConflict("UNKNOWN_REVIEW")
    if not isinstance(evidence, dict) or evidence.get("intent_id") != row[0]:
        raise ValueError("INVALID_RECONCILIATION_EVIDENCE")
    try:
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("INVALID_RECONCILIATION_EVIDENCE") from exc
    observed = hashlib.sha256(canonical).hexdigest()
    return {"review_id": review_id, "intent_id": row[0], "operator_id": row[1],
            "decision": row[2], "created_at": row[4],
            "evidence_matches": hmac.compare_digest(observed, row[3]),
            "authorizes_resume": False}
