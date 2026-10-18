import os
import pytest
from odmm_live_access_v2182 import AccessCase,LiveAccessError
from odmm_access_campaign_v2183 import run_isolated_campaign

def make_case(tmp_path,case_id='c1'):
    src=tmp_path/'source';dst=tmp_path/'target';src.mkdir(exist_ok=True);dst.mkdir(exist_ok=True)
    (src/'data').write_text('ok');(dst/'data').write_text('ok')
    return AccessCase(case_id,str(src),str(dst),'data',os.geteuid(),os.getegid(),'NetApp','OneFS')

def test_isolated_evidence(tmp_path):
    result=run_isolated_campaign([make_case(tmp_path)])
    assert result['report']['all_local_outcomes_equal']
    assert not result['report']['cutover_authorized']
    assert not result['report']['dedicated_account_attested']
    assert len(result['sha256'])==64

def test_identity_mismatch_fails(tmp_path):
    c=make_case(tmp_path)
    c=AccessCase(c.case_id,c.source_root,c.target_root,c.relative_path,c.expected_euid+1,c.expected_egid,c.source_vendor,c.target_vendor)
    with pytest.raises(LiveAccessError,match='WORKER_FAILED_CLOSED'):
        run_isolated_campaign([c])

def test_missing_file_fails(tmp_path):
    c=make_case(tmp_path);(tmp_path/'target'/'data').unlink()
    with pytest.raises(LiveAccessError,match='WORKER_FAILED_CLOSED'):
        run_isolated_campaign([c])

def test_duplicates_fails(tmp_path):
    c=make_case(tmp_path)
    with pytest.raises(LiveAccessError,match='DUPLICATE_CASE'):
        run_isolated_campaign([c,c])

@pytest.mark.parametrize('timeout',[0,-1,301,True])
def test_invalid_timeout(tmp_path,timeout):
    with pytest.raises(LiveAccessError,match='INVALID_TIMEOUT'):
        run_isolated_campaign([make_case(tmp_path)],timeout_seconds=timeout)
