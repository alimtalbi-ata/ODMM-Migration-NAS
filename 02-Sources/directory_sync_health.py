"""Fail-closed, read-only LDAPS synchronization health and recovery qualification.

No network calls or database writes. Input observations are NOT trusted attestations.
"""
import hashlib
import json

class SyncHealthError(ValueError): pass

def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def assess_directory_sync_health(ledger, *, now, max_age_seconds, observations):
    if type(now) is not int or now < 0 or type(max_age_seconds) is not int or max_age_seconds < 1:
        raise SyncHealthError('INVALID_CLOCK_OR_TTL')
    if not isinstance(observations,list) or not observations:
        raise SyncHealthError('OBSERVATIONS_REQUIRED')
    previous=-1
    failures=[]
    last_success=None
    for i,item in enumerate(observations):
        if not isinstance(item,dict) or set(item)!={'at','status','digest'}:
            raise SyncHealthError('INVALID_OBSERVATION')
        at=item['at'];status=item['status'];digest=item['digest']
        if type(at) is not int or at < 0 or at > now or at <= previous:
            raise SyncHealthError('NON_MONOTONIC_OBSERVATION')
        previous=at
        if status not in ('SUCCESS','NETWORK_FAILURE','TLS_FAILURE','PAGINATION_FAILURE','IMPORT_FAILURE'):
            raise SyncHealthError('INVALID_STATUS')
        if status=='SUCCESS':
            if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
                raise SyncHealthError('INVALID_SUCCESS_DIGEST')
            last_success=item
        else:
            if digest is not None:raise SyncHealthError('FAILURE_WITH_DIGEST')
            failures.append({'at':at,'reason':status})
    # Read state without starting a write transaction.
    rows=ledger.db.execute('SELECT source,version,digest FROM directory_sync_state ORDER BY source').fetchall()
    if len(rows)!=1 or rows[0][0]!='LDAP_EXPORT':
        state='BLOCKED_NO_DIRECTORY_BASELINE'
    elif last_success is None:
        state='BLOCKED_NO_SUCCESSFUL_SYNC'
    elif rows[0][2]!=last_success['digest']:
        state='BLOCKED_BASELINE_MISMATCH'
    elif observations[-1]['status']!='SUCCESS':
        state='BLOCKED_LAST_ATTEMPT_FAILED'
    elif now-last_success['at']>max_age_seconds:
        state='BLOCKED_STALE_DIRECTORY'
    else:
        state='OFFLINE_HEALTHY_NOT_AUTHORIZED'
    report={'schema':'odmm.directory-sync-health.v1','status':state,'now':now,
            'max_age_seconds':max_age_seconds,'last_success_at':last_success['at'] if last_success else None,
            'last_attempt_at':observations[-1]['at'],'failure_count':len(failures),
            'failures':failures,'baseline_digest':rows[0][2] if len(rows)==1 and rows[0][0]=='LDAP_EXPORT' else None,
            'cutover_authorized':False,'production_qualified':False,
            'limitations':['OBSERVATIONS_UNAUTHENTICATED','NO_LIVE_DIRECTORY_QUALIFICATION','NO_CUTOVER_AUTHORITY']}
    return {'report':report,'sha256':_digest(report)}

def verify_directory_sync_health(bundle, ledger, *, now, max_age_seconds, observations):
    if bundle != assess_directory_sync_health(ledger,now=now,max_age_seconds=max_age_seconds,observations=observations):
        raise SyncHealthError('HEALTH_REPORT_MISMATCH')
    return True
