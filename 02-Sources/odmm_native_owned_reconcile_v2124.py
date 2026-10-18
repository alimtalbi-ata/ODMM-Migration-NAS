"""V212.4 read-only ownership-gated reconciliation. Author: Abdelhalim Talbi.

Single-host advisory coordination only. No distributed commit, automatic repair or cutover.
"""
from dataclasses import dataclass
from odmm_native_secure_v2120 import Blocked
from odmm_native_reconcile_v2121 import ReconciledStaging
from odmm_native_ownership_v2122 import Claim

@dataclass(frozen=True)
class ReconcileEvidence:
    resource: str
    owner: str
    epoch: int
    entries: tuple
    clean: bool
    cutover_authorized: bool = False
    acl_fidelity_verified: bool = False
    distributed_fencing_verified: bool = False

class OwnedReconciler:
    def __init__(self, staging, registry, claim):
        if not isinstance(staging, ReconciledStaging) or not isinstance(claim, Claim) or not callable(getattr(registry, 'verify', None)):
            raise Blocked('INVALID_OWNED_RECONCILER')
        self.staging, self.registry, self.claim = staging, registry, claim

    def _fence(self):
        try:
            return self.registry.verify(self.claim) is True
        except Exception:
            return False

    def reconcile(self):
        if not self._fence():
            raise Blocked('STALE_OWNER')
        entries = self.staging.reconcile(fence=self._fence)
        if not self._fence():
            raise Blocked('FENCE_LOST')
        clean = bool(entries) and all(e['journal_state'] == 'VERIFIED' and e['target_status'] == 'MATCH' and not e['requires_human_review'] for e in entries)
        return ReconcileEvidence(self.claim.resource, self.claim.owner, self.claim.epoch, tuple(entries), clean)
