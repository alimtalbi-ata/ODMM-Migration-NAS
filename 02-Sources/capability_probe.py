"""Read-only Linux mount capability evidence. Never asserts NAS qualification."""
import hashlib
import json
from mount_attestation import attest_mount


def qualification_matrix(entries):
    """Build deterministic fail-closed report from caller-supplied mount attestations."""
    rows = []
    for entry in entries:
        protocol = entry.get('protocol')
        root = entry.get('mountpoint')
        if protocol not in ('NFSv4', 'SMB') or not isinstance(root, str) or not root.startswith('/'):
            rows.append({'protocol': protocol, 'mountpoint': root, 'status': 'BLOCKED', 'reason': 'INVALID_REQUEST'})
            continue
        try:
            evidence = attest_mount(root, protocol)
            status, reason = 'EVIDENCE_ONLY', 'EFFECTIVE_ACCESS_NOT_VERIFIED'
        except Exception as exc:
            evidence = None
            status, reason = 'BLOCKED', type(exc).__name__
        rows.append({'protocol': protocol, 'mountpoint': root, 'status': status, 'reason': reason,
                     'mount_evidence': evidence, 'production_qualified': False})
    payload = {'schema': 'odmm.capabilities.v1', 'rows': rows, 'production_qualified': False}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode()
    return {'report': payload, 'sha256': hashlib.sha256(canonical).hexdigest()}
