"""Read-only reconciliation evidence for UNCERTAIN local laboratory intents.

No automatic transition, delete, overwrite, or resume. Author: Abdelhalim Talbi.
"""
import hashlib
import json
from pathlib import Path
from odmm_linux_lab_verifier import verify_pair, VerificationError
from odmm_linux_lab_identity_journal import inspect_identity
from odmm_linux_lab_external_anchor import verify_anchor

class ReconciliationError(RuntimeError):
    pass

def inspect_uncertain(db, intent_id, source, target, *, anchor_dir=None, key_resolver=None):
    """Optional external anchor verification is advisory and never permits replay."""
    if (anchor_dir is None) != (key_resolver is None):
        raise ValueError("ANCHOR_CONFIGURATION_INCOMPLETE")
    if not isinstance(intent_id, str) or not intent_id or len(intent_id) > 128:
        raise ValueError("INVALID_INTENT_ID")
    row = db.execute("""SELECT task_id,owner,fence_token,payload_sha256,state
        FROM odmm_datamover_intents WHERE intent_id=?""", (intent_id,)).fetchone()
    if row is None:
        raise ReconciliationError("UNKNOWN_INTENT")
    if row[4] != "UNCERTAIN":
        raise ReconciliationError("INTENT_NOT_UNCERTAIN")
    source, target = Path(source), Path(target)
    if source.is_symlink():
        raise ReconciliationError("SOURCE_SYMLINK_REFUSED")
    payload = {"kind": "local-lab-copy-v1", "source": str(source.resolve()),
               "target": str(target.absolute())}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != row[3]:
        raise ReconciliationError("INTENT_PAYLOAD_MISMATCH")
    result = {"intent_id": intent_id, "task_id": row[0], "state": "UNCERTAIN",
              "decision": "MANUAL_REVIEW_REQUIRED", "target_present": False,
              "content_verified": False, "nas_acl_qualified": False,
              "identity_evidence": inspect_identity(db, intent_id, source, target)}
    if anchor_dir is not None:
        result["external_anchor"] = verify_anchor(db, intent_id, anchor_dir,
                                                   key_resolver=key_resolver)
    if target.is_symlink():
        result["reason"] = "TARGET_SYMLINK_REFUSED"
        return result
    if not target.exists():
        result["reason"] = "TARGET_ABSENT"
        return result
    result["target_present"] = True
    try:
        evidence = verify_pair(source, target)
        result["content_verified"] = bool(evidence["verified"])
        result["reason"] = "LOCAL_CONTENT_AND_MODE_MATCH"
        result["sha256"] = evidence["target"]["sha256"]
    except VerificationError as exc:
        result["reason"] = str(exc)
    return result
