import pytest
from odmm_group_membership_v2189 import preflight_group_graph, GroupPreflightError

def test_nested():
    p=preflight_group_graph({'admins':['operators'],'operators':['alice']},['alice'])
    assert p['report']['resolved_groups']['admins']==['alice']
    assert p['report']['cutover_authorized'] is False

def test_determinism():
    assert preflight_group_graph({'a':['x'],'b':['a']},['x'])==preflight_group_graph({'b':['a'],'a':['x']},['x'])

@pytest.mark.parametrize('groups,users,error',[
    ({'a':['b'],'b':['a']},['x'],'GROUP_CYCLE'),
    ({'a':['missing']},['x'],'UNRESOLVED_OR_DUPLICATE_MEMBER'),
    ({'a':['x','x']},['x'],'UNRESOLVED_OR_DUPLICATE_MEMBER'),
    ({'x':['x']},['x'],'AMBIGUOUS_PRINCIPAL'),
    ({'a':['b'],'b':['c'],'c':['x']},['x'],'MAX_DEPTH_EXCEEDED'),
])
def test_rejected(groups,users,error):
    with pytest.raises(GroupPreflightError,match=error):
        preflight_group_graph(groups,users,max_depth=1)
