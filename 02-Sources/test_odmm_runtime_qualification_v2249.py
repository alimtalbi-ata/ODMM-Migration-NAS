"""Runtime qualification regression. Author: Abdelhalim Talbi."""
from odmm_runtime_qualification_v2249 import qualify

def test_runtime_smoke():
    result=qualify()
    assert result['status']=='PASS_WITH_UNQUALIFIED_ITEMS'
    assert all(c['status']=='PASS' for c in result['checks'][:5])
    assert all(c['status']=='NOT_TESTED' for c in result['checks'][5:])
