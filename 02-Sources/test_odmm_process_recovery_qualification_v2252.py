from odmm_process_recovery_qualification_v2252 import qualify

def test_process_kill_recovery():
    result = qualify()
    assert result['status'] == 'PASS_WITH_UNQUALIFIED_ITEMS', result
    assert sum(x['status'] == 'PASS' for x in result['checks']) >= 5

def test_no_unsupported_claims():
    result = qualify()
    pending = {x['name'] for x in result['checks'] if x['status'] == 'NOT_TESTED'}
    assert {'windows-portable-execution', 'nfs-smb-real-nas', 'effective-acl-identity', 'mid-file-crash-atomicity'} <= pending
