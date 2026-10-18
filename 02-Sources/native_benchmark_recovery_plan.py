"""V192.3: non-mutating evidence-first human recovery workflow.

Approval permits creation of a *plan*, never mutation of the journal.
"""
import hashlib
import hmac
import os
from pathlib import Path
from native_benchmark_integrity import _open
from native_benchmark_recovery import diagnose_authenticated


def prepare_recovery(path, *, keys, trusted_head=None):
    """Create a sanitized recovery proposal tied to exact original file bytes."""
    diagnosis = diagnose_authenticated(path, keys=keys, trusted_head=trusted_head)
    try:
        fd = _open(path, readonly=True)
    except FileNotFoundError:
        fd = None
    if fd is None:
        digest = None
        length = 0
    else:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_SH)
            st = os.fstat(fd)
            if not os.path.isfile(path) or not __import__('stat').S_ISREG(st.st_mode):
                raise ValueError('UNSAFE_EVIDENCE')
            h = hashlib.sha256()
            length = 0
            while True:
                block = os.read(fd, 65536)
                if not block: break
                length += len(block)
                if length > 20_000_000: raise ValueError('EVIDENCE_TOO_LARGE')
                h.update(block)
            digest = h.hexdigest()
        finally:
            os.close(fd)
    return {'schema':'odmm.benchmark.recovery_plan.v1',
            'status':'REVIEW_REQUIRED' if diagnosis['status']=='BLOCKED' else 'NO_REPAIR_REQUIRED',
            'diagnosis':diagnosis, 'evidence_sha256':digest,'evidence_bytes':length,
            'approved':False,'mutations_performed':False,'cutover_authorized':False,
            'next_step':'PRESERVE_ORIGINAL_AND_ESCALATE_TO_HUMAN'}


def validate_manual_approval(plan, *, evidence_sha256, operator, rationale, approval_token):
    """Validate explicit approval of an immutable evidence digest; no repair action."""
    if plan.get('schema')!='odmm.benchmark.recovery_plan.v1' or plan.get('status')!='REVIEW_REQUIRED':
        raise ValueError('NO_RECOVERY_APPROVAL_POSSIBLE')
    if not isinstance(evidence_sha256,str) or not hmac.compare_digest(str(plan.get('evidence_sha256')),evidence_sha256):
        raise ValueError('EVIDENCE_MISMATCH')
    if not all(isinstance(x,str) and len(x.strip())>=8 for x in (operator,rationale,approval_token)):
        raise ValueError('EXPLICIT_APPROVAL_REQUIRED')
    return {'status':'APPROVAL_RECORDED_FOR_EXTERNAL_REVIEW',
            'evidence_sha256':evidence_sha256,'operator':operator.strip(),
            'mutations_performed':False,'repair_authorized':False,'cutover_authorized':False}
