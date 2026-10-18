from odmm_midcopy_crash_qualification_v2253 import qualify

def test_midcopy_crash_and_recovery():
    result = qualify()
    assert result['status'] == 'PASS_WITH_UNQUALIFIED_ITEMS', result
    assert sum(c['status'] == 'PASS' for c in result['checks']) >= 8

def test_unqualified_items_reported():
    result = qualify()
    assert sum(c['status'] == 'NOT_TESTED' for c in result['checks']) == 4
