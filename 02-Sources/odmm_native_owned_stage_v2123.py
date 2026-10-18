"""V212.3 ownership-gated native staging. Author: Abdelhalim Talbi.

Single-host advisory fencing. Not a distributed atomic commit or NAS cutover gate.
"""
from dataclasses import dataclass
from odmm_native_ownership_v2122 import Claim, OwnershipBlocked
from odmm_native_secure_v2120 import Blocked, SecureStaging

@dataclass(frozen=True)
class OwnedStageResult:
    path: str
    sha256: str
    epoch: int
    resource: str
    state: str = 'VERIFIED'
    engine: str = 'ODMM_NATIVE'
    cutover_authorized: bool = False
    acl_fidelity_verified: bool = False
    distributed_fencing_verified: bool = False

class OwnedStaging:
    def __init__(self, staging: SecureStaging, registry, claim: Claim):
        if not isinstance(staging, SecureStaging) or not isinstance(claim, Claim) or not callable(getattr(registry, 'verify', None)):
            raise Blocked('INVALID_OWNED_STAGING')
        self.staging, self.registry, self.claim = staging, registry, claim

    def _fence(self):
        try:
            return self.registry.verify(self.claim) is True
        except Exception:
            return False

    def stage(self, name):
        if not self._fence():
            raise Blocked('STALE_OWNER')
        # SecureStaging checks this predicate before reading and just before publishing.
        # This is advisory: registry changes can still race after the final check.
        result = self.staging.stage(name, fence=self._fence)
        return OwnedStageResult(result['path'], result['sha256'], self.claim.epoch, self.claim.resource)

    def pending(self):
        if not self._fence():
            raise Blocked('STALE_OWNER')
        return self.staging.pending()
