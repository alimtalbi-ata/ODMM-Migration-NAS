from datetime import datetime, timezone
from odmm_health_v2271 import summarize, format_summary
NOW=datetime(2026,10,17,tzinfo=timezone.utc)

def test_empty():
    result=summarize([],[],NOW)
    assert all(value == 0 for value in result.values())
    assert 'Jobs : 0' in format_summary(result)

def test_counts_and_unknown():
    jobs=[{'status':'BLOCKED'},{'status':'FAILED'},{'status':'RUNNING'}]
    ops=[{'state':'FAILED','lease_until':None},{'state':'RUNNING','lease_until':'2026-10-16T00:00:00Z'}, {'state':'RUNNING','lease_until':'2026-10-16T00:00:00'}]
    s=summarize(jobs,ops,NOW)
    assert (s['jobs_blocked'],s['jobs_failed'],s['operations_failed'],s['leases_expired_local'],s['leases_unknown'])==(1,1,1,1,1)

def test_non_running_lease_not_flagged():
    s=summarize([],[{'state':'DONE','lease_until':'2020-01-01T00:00:00Z'}],NOW)
    assert s['leases_expired_local']==0
