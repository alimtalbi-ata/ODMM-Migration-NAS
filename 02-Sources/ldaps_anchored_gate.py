"""Opt-in external anchor enforcement at startup and before RBAC review.

The HMAC key must be held outside SQLite and injected by the caller. An anchor
cannot be repaired automatically. Rotation requires the old key and an unchanged
verified state; it is not atomic across two independent files.
"""
import os
from ldaps_external_anchor import ExternalPolicyAnchor, ExternalAnchorError
from ldaps_security_startup import verify_startup


def verify_anchored_startup(rbac, *, now, anchor_path, key):
    verify_startup(rbac, now=now, require_audited_policy=True)
    ExternalPolicyAnchor(rbac, anchor_path=anchor_path, key=key).verify()
    return {'status':'ANCHORED_STARTUP_PASSED','review_allowed':True,
            'execution_authorized':False,'cutover_authorized':False}


def rotate_anchor_key(rbac, *, now, anchor_path, old_key, new_key):
    """Operator-controlled rotation; old anchor MUST verify before new write."""
    if not isinstance(new_key,bytes) or len(new_key)<32 or new_key==old_key:
        raise ExternalAnchorError('INVALID_ROTATION_KEY')
    verify_anchored_startup(rbac,now=now,anchor_path=anchor_path,key=old_key)
    # Atomic replacement of a single file; secure key distribution is external.
    result=ExternalPolicyAnchor(rbac,anchor_path=anchor_path,key=new_key).checkpoint()
    return {**result,'status':'ANCHOR_KEY_ROTATED','execution_authorized':False,'cutover_authorized':False}


class AnchoredReviewGate:
    """Explicit secure facade; never expose the raw RBAC object to reviewers."""
    def __init__(self, rbac, *, anchor_path, key):
        self.rbac=rbac
        self.anchor_path=anchor_path
        self.key=key

    def startup(self, *, now):
        return verify_anchored_startup(self.rbac,now=now,anchor_path=self.anchor_path,key=self.key)

    def decide(self, event_id, request_id, *, observation_hash, reviewer, action,
               decided_at, max_age_seconds=3600):
        # Hold a SQLite write lock over both the anchor check and decision.
        # RBAC.decide() manages its own transaction; a guarded hook verifies
        # inside that transaction as well, avoiding a check/use gap.
        return self.rbac.decide(event_id,request_id,observation_hash=observation_hash,
                                reviewer=reviewer,action=action,decided_at=decided_at,
                                max_age_seconds=max_age_seconds,
                                _external_anchor=(self.anchor_path,self.key))
