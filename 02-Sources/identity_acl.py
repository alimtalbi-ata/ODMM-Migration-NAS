"""ODMM V177.4: conservative, read-only canonical identity and ACL evidence.
No access is granted or inferred from opaque ACL blobs.
"""
from dataclasses import dataclass, asdict
from hashlib import sha256
import json

class IdentityConflict(ValueError): pass

@dataclass(frozen=True)
class Principal:
    realm: str
    kind: str
    identifier: str
    canonical_id: str

    def __post_init__(self):
        if self.kind not in ('user', 'group') or not all((self.realm, self.identifier, self.canonical_id)):
            raise ValueError('invalid principal')

class IdentityMap:
    def __init__(self, entries):
        self._mapping = {}
        self._reverse = {}
        for source, target in entries:
            if source.kind != target.kind:
                raise IdentityConflict('principal kind mismatch')
            k = (source.realm, source.kind, source.identifier)
            t = (target.realm, target.kind, target.identifier)
            if k in self._mapping and self._mapping[k] != target:
                raise IdentityConflict('ambiguous source mapping')
            if t in self._reverse and self._reverse[t] != source:
                raise IdentityConflict('many-to-one mapping requires review')
            self._mapping[k] = target
            self._reverse[t] = source

    def resolve(self, principal):
        return self._mapping.get((principal.realm, principal.kind, principal.identifier))

@dataclass(frozen=True)
class ACE:
    principal: Principal
    effect: str
    rights: tuple
    inherited: bool = False

    def __post_init__(self):
        if self.effect not in ('allow', 'deny') or not self.rights or any(r not in ('read','write','execute','delete','change_acl','take_ownership') for r in self.rights):
            raise ValueError('invalid ACE')


def canonical_fingerprint(aces):
    """Evidence fingerprint only; not a proof of effective permissions."""
    payload = [asdict(a) for a in aces]
    return sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def compare_acl(source_aces, target_aces, mapping, *, source_complete=False, target_complete=False, identity_verified=False):
    """Fail closed. Never declare effective-access equivalence without real probes."""
    mapped = []
    missing = []
    for ace in source_aces:
        target = mapping.resolve(ace.principal)
        if target is None:
            missing.append(asdict(ace.principal))
        else:
            mapped.append(ACE(target, ace.effect, ace.rights, ace.inherited))
    differences = []
    if not missing and mapped != list(target_aces):
        differences.append('ACL_ORDER_OR_CONTENT_MISMATCH')
    if not source_complete or not target_complete:
        differences.append('INCOMPLETE_ACL_EVIDENCE')
    if not identity_verified:
        differences.append('IDENTITY_NOT_VERIFIED')
    status = 'BLOCKED' if missing or 'ACL_ORDER_OR_CONTENT_MISMATCH' in differences else 'INDETERMINATE'
    return {'status': status, 'missing_mappings': missing, 'differences': differences,
            'source_fingerprint': canonical_fingerprint(source_aces),
            'target_fingerprint': canonical_fingerprint(target_aces),
            'effective_access_verified': False,
            'requires_live_access_tests': True}


def access_test_matrix(principals, paths, rights=('read','write','execute','delete')):
    """Generate test specifications, never execute or claim permissions."""
    return [{'principal': asdict(p), 'path': path, 'right': right, 'result': 'NOT_RUN'}
            for p in principals for path in paths for right in rights]
