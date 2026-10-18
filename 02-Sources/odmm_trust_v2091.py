"""External secret resolver, audit checkpoints and ONTAP LIF assessment.
Author: Abdelhalim Talbi. Read-only qualification, never authorizes cutover.
"""
import hashlib
import hmac
import json
import re
from odmm_netapp_collector_v2089 import CollectorError


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


class ExternalSecretResolver:
    """Adapter to a trusted secret backend; no secrets stored in this object or SQLite.

    fetch_secret(collector_id, key_id) must return a 32+ byte secret via a secured
    channel; rotation and revocation remain managed by the backend.
    """
    def __init__(self, fetch_secret):
        if not callable(fetch_secret):
            raise TypeError('SECRET_BACKEND_REQUIRED')
        self.fetch_secret = fetch_secret

    def resolve(self, collector, kid):
        if not all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', v) for v in (collector, kid)):
            raise CollectorError('IDENTIFIER_INVALID')
        try:
            key = self.fetch_secret(collector, kid)
        except Exception as exc:
            raise CollectorError('SECRET_BACKEND_UNAVAILABLE') from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise CollectorError('SECRET_UNAVAILABLE')
        return key


def sign_audit_checkpoint(rows, *, signer_id, key):
    """HMAC checkpoint. Not a third-party signature or public-key attestation."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise CollectorError('WEAK_KEY')
    from odmm_collector_registry_v2090 import CollectorRegistry
    if not rows or not CollectorRegistry.verify_audit(rows):
        raise CollectorError('AUDIT_INVALID')
    body = {'schema': 'odmm.audit.checkpoint.v2091', 'signer_id': signer_id,
            'sequence': rows[-1]['seq'], 'head': rows[-1]['entry_hash']}
    if not isinstance(signer_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', signer_id):
        raise CollectorError('SIGNER_INVALID')
    return {**body, 'mac': hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()}


def verify_audit_checkpoint(rows, checkpoint, *, resolver):
    try:
        from odmm_collector_registry_v2090 import CollectorRegistry
        if not isinstance(checkpoint, dict) or set(checkpoint) != {'schema','signer_id','sequence','head','mac'}:
            return False
        if checkpoint['schema'] != 'odmm.audit.checkpoint.v2091' or not rows or not CollectorRegistry.verify_audit(rows):
            return False
        if checkpoint['sequence'] != rows[-1]['seq'] or checkpoint['head'] != rows[-1]['entry_hash']:
            return False
        body = {k:v for k,v in checkpoint.items() if k != 'mac'}
        expected = hmac.new(resolver.resolve('audit', checkpoint['signer_id']), _canonical(body), hashlib.sha256).hexdigest()
        return isinstance(checkpoint['mac'], str) and hmac.compare_digest(expected, checkpoint['mac'])
    except (CollectorError, ValueError, TypeError, KeyError):
        return False


def assess_lif_failover(source, target):
    """Compare explicit LIF observations; never infers session continuity.

    Required fields: lif_id, svm, protocol, home_node, current_node,
    operational, session_revalidated. An actual failover requires independently
    measured client session revalidation on target.
    """
    blockers = []
    if not isinstance(source, list) or not isinstance(target, list) or not source or not target:
        blockers.append('LIF_EVIDENCE_MISSING')
    def index(rows, side):
        result = {}
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict) or any(k not in row for k in ('lif_id','svm','protocol','home_node','current_node','operational','session_revalidated')):
                blockers.append(side+'_LIF_SCHEMA_INVALID'); continue
            key = (row['svm'], row['lif_id'], row['protocol'])
            if not all(isinstance(v, str) and v for v in key) or key in result:
                blockers.append(side+'_LIF_DUPLICATE_OR_INVALID'); continue
            if row['protocol'] not in ('SMB','NFSv3','NFSv4'):
                blockers.append(side+'_PROTOCOL_UNSUPPORTED')
            result[key] = row
        return result
    a,b=index(source,'SOURCE'),index(target,'TARGET')
    for key in a.keys() | b.keys():
        if key not in a or key not in b:
            blockers.append('LIF_MAPPING_MISSING'); continue
        if b[key]['operational'] is not True:
            blockers.append('TARGET_LIF_NOT_OPERATIONAL')
        if a[key]['current_node'] != b[key]['current_node'] and b[key]['session_revalidated'] is not True:
            blockers.append('SESSION_CONTINUITY_NOT_PROVEN')
    blockers.append('CUTOVER_REQUIRES_INDEPENDENT_APPROVAL')
    return {'schema':'odmm.netapp.lif-assessment.v2091','status':'BLOCKED',
            'cutover_authorized':False,'blockers':sorted(set(blockers)),
            'lif_pairs':len(a.keys() & b.keys())}
