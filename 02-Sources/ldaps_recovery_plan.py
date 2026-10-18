"""Read-only, fail-closed LDAPS crash recovery plan. Never retries or authorizes cutover."""
import re
from directory_sync_journal import DirectorySyncJournal, digest

class RecoveryPlanError(ValueError): pass

def build_recovery_plan(coordinator, *, now, max_age_seconds):
    if type(now) is not int or now < 0 or type(max_age_seconds) is not int or max_age_seconds <= 0:
        raise RecoveryPlanError('INVALID_TIME')
    db=coordinator.db
    # No writes: classify STARTED intents against durable journal in memory.
    journal=DirectorySyncJournal(db)
    journal_state=journal.verify()
    rows=db.execute('SELECT event_id,started_at,state,detail FROM ldaps_attempt_intents ORDER BY started_at,event_id').fetchall()
    events={r[0]:(r[1],r[2]) for r in db.execute('SELECT event_id,at,status FROM directory_sync_events')}
    plans=[]
    for event_id,started,state,detail in rows:
        ev=events.get(event_id)
        if state=='STARTED':
            effective='COMMITTED' if ev and ev[1]=='SUCCESS' else 'FAILED' if ev else 'INTERRUPTED'
        else:
            effective=state
        contradictions=(state=='COMMITTED' and (not ev or ev[1]!='SUCCESS')) or (state=='FAILED' and (not ev or ev[1]=='SUCCESS')) or (state=='INTERRUPTED' and ev is not None)
        if contradictions: action='INVESTIGATE_CONTRADICTORY_EVIDENCE'
        elif effective=='INTERRUPTED': action='MANUAL_REVIEW_BEFORE_NEW_ATTEMPT'
        elif effective=='FAILED': action='REVIEW_FAILURE_AND_DIRECTORY_STATE'
        elif effective=='COMMITTED': action='VERIFY_DIRECTORY_BASELINE_AND_APPROVALS'
        else: action='INVESTIGATE_UNKNOWN_STATE'
        if started>now or (ev and ev[0]>now): action='INVESTIGATE_FUTURE_TIMESTAMP'
        if now-started>max_age_seconds and effective!='COMMITTED': action='REVIEW_STALE_ATTEMPT' if not contradictions else action
        plans.append({'event_id':event_id,'persisted_state':state,'effective_state':effective,
                      'journal_status':ev[1] if ev else None,'action':action,
                      'human_review_required':True,'automatic_retry':False,'cutover_authorized':False})
    report={'schema':'odmm.ldaps-recovery-plan.v1','evaluated_at':now,'max_age_seconds':max_age_seconds,
            'journal_head_hash':journal_state['head_hash'],'attempts':plans,
            'status':'REVIEW_REQUIRED' if plans else 'NO_ATTEMPTS_NOT_AUTHORIZED',
            'automatic_retry':False,'cutover_authorized':False,'production_qualified':False,
            'limitations':['NO_LIVE_DIRECTORY_ATTESTATION','NO_AUTOMATIC_REPLAY','HUMAN_APPROVAL_REQUIRED']}
    return {'report':report,'sha256':digest(report)}

def verify_recovery_plan(bundle,coordinator,*,now,max_age_seconds):
    if bundle!=build_recovery_plan(coordinator,now=now,max_age_seconds=max_age_seconds):
        raise RecoveryPlanError('REPORT_MISMATCH')
    return True
