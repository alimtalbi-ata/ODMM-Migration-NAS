from datetime import datetime, timezone
from odmm_dashboard_v2270 import filter_jobs, filter_operations, lease_indicator

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)

def test_job_filters():
    rows = [{'id':'Job-ABC','status':'RUNNING'}, {'id':'Job-DEF','status':'FAILED'}]
    assert len(filter_jobs(rows, 'abc')) == 1
    assert filter_jobs(rows, status='FAILED')[0]['id'] == 'Job-DEF'
    assert filter_jobs(rows, 'unknown') == []

def test_lease_expiration():
    base = {'state':'RUNNING','lease_until':'2026-10-16T12:00:00Z'}
    assert lease_indicator(base, NOW).startswith('Expiré')
    assert lease_indicator({**base, 'lease_until':'2026-10-18T12:00:00+00:00'}, NOW).startswith('Actif')
    assert lease_indicator({**base, 'lease_until':'2026-10-16T12:00:00'}, NOW) == 'Inconnu'
    assert lease_indicator({**base, 'lease_until':123456}, NOW) == 'Inconnu'
    assert lease_indicator({**base, 'state':'DONE'}, NOW) == '—'

def test_operation_filters():
    rows = [{'id':'OP-1','state':'RUNNING','owner':'alice','lease_until':'2026-10-16T12:00:00Z'},
            {'id':'OP-2','state':'FAILED','owner':None,'lease_until':None}]
    assert len(filter_operations(rows, 'alice')) == 1
    assert len(filter_operations(rows, state='FAILED')) == 1
    assert [r['id'] for r in filter_operations(rows, expired_only=True, now=NOW)] == ['OP-1']
