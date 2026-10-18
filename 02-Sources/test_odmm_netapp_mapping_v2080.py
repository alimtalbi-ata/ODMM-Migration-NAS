from odmm_netapp_services_v2079 import ServiceInventory
from odmm_netapp_mapping_v2080 import correlate_ontap_services,compare_mappings,render_mapping_html

def inv(*,style='mixed',path='/data',share='/data/team',policy='default',svm='s1'):
    r={'volumes':({'name':'vol1','svm':{'uuid':svm},'nas':{'path':path,'security_style':style,'export_policy':policy}},),
       'cifs_shares':({'name':'team','svm':{'uuid':svm},'path':share},),
       'nfs_export_policies':({'name':policy,'svm':{'uuid':svm}},),
       'lifs':({'name':'lif1','svm':{'uuid':svm}},)}
    return ServiceInventory(r,(),(),{})

def test_mapping():
    m=correlate_ontap_services(inv());assert m.rows[0]['shares']==['team'];assert m.rows[0]['lif_count']==1;assert not m.cutover_authorized

def test_orphan():assert 'NETAPP_ORPHAN_OR_UNMAPPED_SHARE' in correlate_ontap_services(inv(share='/other')).blockers

def test_missing_policy():assert 'NETAPP_EXPORT_POLICY_UNRESOLVED' in correlate_ontap_services(inv(policy='absent').__class__({**inv().resources,'nfs_export_policies':()},(),(),{})).blockers

def test_bad_path():assert 'NETAPP_VOLUME_NAMESPACE_UNVERIFIED' in correlate_ontap_services(inv(path='../bad')).blockers

def test_no_lif():
    x=inv(); y=ServiceInventory({**x.resources,'lifs':()},(),(),{})
    assert 'NETAPP_SVM_LIF_MAPPING_MISSING' in correlate_ontap_services(y).blockers

def test_escaped_dashboard():
    r=compare_mappings(inv(share='/data/<script>'),inv());html=render_mapping_html(r)
    assert '<script>' not in html and 'CUTOVER INTERDIT' in html

def test_pair_blocked():assert compare_mappings(inv(),inv())['cutover_authorized'] is False
