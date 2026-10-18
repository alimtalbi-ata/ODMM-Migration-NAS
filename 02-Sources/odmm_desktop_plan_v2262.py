"""Safe planning handoff: no execution, no credentials, no automatic cutover."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 'odmm.desktop.plan.v1'

def create_plan(preflight, *, operator_ack=False):
    if not isinstance(preflight, dict) or preflight.get('status') not in ('PRECHECK_ONLY', 'BLOCKED'):
        raise ValueError('INVALID_PREFLIGHT')
    issues = preflight.get('issues')
    if not isinstance(issues, list) or not isinstance(preflight.get('entries'), list):
        raise ValueError('INVALID_INVENTORY')
    if preflight['status'] == 'PRECHECK_ONLY' and issues:
        raise ValueError('INCONSISTENT_PREFLIGHT')
    if preflight['status'] == 'BLOCKED' and not issues:
        raise ValueError('INCONSISTENT_PREFLIGHT')
    canonical = json.dumps(preflight, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return {
        'schema': SCHEMA, 'created_utc': datetime.now(timezone.utc).isoformat(),
        'source': preflight.get('source'), 'target': preflight.get('target'),
        'files': preflight.get('files'), 'bytes': preflight.get('bytes'),
        'preflight_sha256': hashlib.sha256(canonical).hexdigest(),
        'state': 'BLOCKED' if issues else 'READY_FOR_SERVER_REVIEW',
        'operator_reviewed': bool(operator_ack),
        'execution_authorized': False, 'cutover_authorized': False,
        'engine': 'ODMM_NATIVE_PRIMARY', 'fallback': 'EXPLICIT_APPROVAL_REQUIRED',
        'requirements': ['SERVER_AUTHENTICATION', 'EFFECTIVE_ACL_VALIDATION', 'NAS_PROTOCOL_VALIDATION', 'OPERATOR_APPROVAL'],
        'issues': issues,
        'warning': 'Planning artifact only; not an executable migration job. Local preflight cannot prove ACL/SMB/NFS fidelity.'
    }

def export_plan(path, plan):
    if plan.get('schema') != SCHEMA or plan.get('execution_authorized') is not False or plan.get('cutover_authorized') is not False:
        raise ValueError('UNSAFE_PLAN')
    with open(Path(path), 'x', encoding='utf-8') as stream:
        json.dump(plan, stream, ensure_ascii=False, indent=2)
