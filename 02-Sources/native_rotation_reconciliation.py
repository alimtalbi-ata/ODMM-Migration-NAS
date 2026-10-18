"""V195.5: read-only inspection of admitted rotations. Never retries an effect."""
import re
_ID=re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")

def inspect_rotation_outcome(*,audit,request_id):
    if not isinstance(request_id,str) or not _ID.fullmatch(request_id):
        raise ValueError('RECONCILIATION_REQUEST_ID_INVALID')
    events=audit.export_verified()['events']
    relevant={e['event_id']:e for e in events if e.get('event_id') in
        ('admit:'+request_id,'uncertain:'+request_id,'complete:'+request_id)}
    if 'admit:'+request_id not in relevant:
        return {'request_id':request_id,'state':'NOT_ADMITTED','retry_allowed':False}
    if 'complete:'+request_id in relevant:
        state='EFFECT_RETURNED_UNVERIFIED'
    elif 'uncertain:'+request_id in relevant:
        state='OUTCOME_UNCERTAIN'
    else:
        state='ADMITTED_PENDING_RECONCILIATION'
    return {'request_id':request_id,'state':state,'retry_allowed':False,
            'evidence_required':True}
