"""Consolidated read-only qualification reports. Author: Abdelhalim Talbi."""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from odmm_trust_v2091 import assess_lif_failover


def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(',', ':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def consolidate(*, campaign_id, source_lifs, target_lifs, migration_preflight, audit_rows, checkpoint, checkpoint_resolver, observed_at=None):
    """Report evidence without claiming external hardware/identity validation."""
    from odmm_trust_v2091 import verify_audit_checkpoint
    from odmm_collector_registry_v2090 import CollectorRegistry
    if not isinstance(campaign_id,str) or not campaign_id or len(campaign_id)>128:
        raise ValueError('CAMPAIGN_ID_REQUIRED')
    lif=assess_lif_failover(source_lifs,target_lifs)
    audit_valid=bool(audit_rows and CollectorRegistry.verify_audit(audit_rows))
    checkpoint_valid=bool(audit_valid and verify_audit_checkpoint(audit_rows,checkpoint,resolver=checkpoint_resolver))
    if not isinstance(migration_preflight,dict) or migration_preflight.get('cutover_authorized') is not False:
        migration_preflight={'status':'BLOCKED','reason':'PREFLIGHT_INVALID','cutover_authorized':False}
    blockers=sorted(set(lif['blockers']+(['AUDIT_CHAIN_INVALID'] if not audit_valid else [])+(['AUDIT_CHECKPOINT_INVALID'] if not checkpoint_valid else [])+[migration_preflight.get('reason','MIGRATION_PREFLIGHT_BLOCKED')]))
    report={'schema':'odmm.qualification.v2094','campaign_id':campaign_id,'observed_at':observed_at or datetime.now(timezone.utc).isoformat(), 'status':'BLOCKED','cutover_authorized':False,'lif':lif,'audit_chain_valid':audit_valid,'checkpoint_valid':checkpoint_valid,'migration_preflight':migration_preflight,'blockers':blockers,'limitations':['EVIDENCE_PROVIDED_BY_CALLER','NO_INDEPENDENT_ONTAP_TEST','NO_CUTOVER_APPROVAL']}
    report['sha256']=hashlib.sha256(canonical(report)).hexdigest()
    return report


def verify_report_digest(report):
    if not isinstance(report,dict) or not isinstance(report.get('sha256'),str):return False
    body={k:v for k,v in report.items() if k!='sha256'}
    try:return hmac.compare_digest(hashlib.sha256(canonical(body)).hexdigest(),report['sha256'])
    except (TypeError,ValueError,OverflowError):return False


def migration_runbook(preflight, *, backup_verified=False, vault_refs_verified=False, rotation_verified=False, independent_approval=False):
    """Produces an operator checklist; never migrates, reads, or exports legacy keys."""
    steps=[('legacy_preflight',isinstance(preflight,dict) and preflight.get('reason')=='OFFLINE_MIGRATION_AND_VAULT_REKEY_REQUIRED'),('immutable_backup',backup_verified is True),('external_vault_refs',vault_refs_verified is True),('key_rotation',rotation_verified is True),('independent_approval',independent_approval is True)]
    return {'schema':'odmm.migration.runbook.v2094','status':'READY_FOR_MANUAL_REVIEW' if all(ok for _,ok in steps) else 'BLOCKED','steps':[{'name':name,'verified':ok} for name,ok in steps],'cutover_authorized':False,'legacy_secrets_exported':False,'automatic_migration':False}
