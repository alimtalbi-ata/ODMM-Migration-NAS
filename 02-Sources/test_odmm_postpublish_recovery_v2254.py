from odmm_postpublish_recovery_v2254 import qualify

def test_postpublish_recovery():
    result=qualify()
    assert result['status']=='PASS_WITH_UNQUALIFIED_ITEMS', result
    assert all(c['status']=='PASS' for c in result['checks'] if c['status']!='NOT_TESTED'), result

def test_explicit_crash_and_corruption_checks():
    checks={c['name']:c for c in qualify()['checks']}
    for key in ('post-publish-crash','intent-durable','commit-not-recorded','explicit-reconcile','atomic-final-register','tampered-destination-rejected','corrupt-intent-remains'):
        assert checks[key]['status']=='PASS', checks[key]
