import pytest
from odmm_trust_v2091 import ExternalSecretResolver,sign_audit_checkpoint,verify_audit_checkpoint,assess_lif_failover
from odmm_collector_registry_v2090 import CollectorRegistry
from odmm_netapp_collector_v2089 import CollectorError
KEY=b'k'*32

def test_external_resolver():
    assert ExternalSecretResolver(lambda c,k:KEY).resolve('agent','key')==KEY
    with pytest.raises(CollectorError,match='IDENTIFIER_INVALID'):
        ExternalSecretResolver(lambda c,k:KEY).resolve('../etc','key')
    with pytest.raises(CollectorError,match='SECRET_BACKEND_UNAVAILABLE'):
        ExternalSecretResolver(lambda c,k:1/0).resolve('agent','key')
    with pytest.raises(CollectorError,match='SECRET_UNAVAILABLE'):
        ExternalSecretResolver(lambda c,k:None).resolve('agent','key')

def test_checkpoint_integrity(tmp_path):
    r=CollectorRegistry(tmp_path/'registry.db');r.register_key('a','b',KEY)
    rows=r.export_audit();cp=sign_audit_checkpoint(rows,signer_id='audit-key',key=KEY)
    resolver=ExternalSecretResolver(lambda c,k: KEY if (c,k)==('audit','audit-key') else None)
    assert verify_audit_checkpoint(rows,cp,resolver=resolver)
    rows[0]['details']['kid']='tampered'
    assert not verify_audit_checkpoint(rows,cp,resolver=resolver)

def test_checkpoint_wrong_key_and_truncation(tmp_path):
    r=CollectorRegistry(tmp_path/'registry.db');r.register_key('a','b',KEY);r.register_key('a','c',KEY)
    rows=r.export_audit();cp=sign_audit_checkpoint(rows,signer_id='signer',key=KEY)
    assert not verify_audit_checkpoint(rows,cp,resolver=ExternalSecretResolver(lambda c,k:b'z'*32))
    assert not verify_audit_checkpoint(rows[:-1],cp,resolver=ExternalSecretResolver(lambda c,k:KEY))
    with pytest.raises(CollectorError,match='AUDIT_INVALID'):
        sign_audit_checkpoint([],signer_id='signer',key=KEY)

def lif(node='n1',verified=True):
    return {'lif_id':'lif1','svm':'svm1','protocol':'SMB','home_node':'n1','current_node':node,'operational':True,'session_revalidated':verified}

def test_lif_failover():
    assert 'SESSION_CONTINUITY_NOT_PROVEN' in assess_lif_failover([lif()],[lif('n2',False)])['blockers']
    assert 'SESSION_CONTINUITY_NOT_PROVEN' not in assess_lif_failover([lif()],[lif('n2',True)])['blockers']
    assert assess_lif_failover([lif()],[lif('n2',True)])['cutover_authorized'] is False
    assert 'LIF_MAPPING_MISSING' in assess_lif_failover([lif()],[])['blockers']

def test_lif_duplicate_and_schema():
    assert 'TARGET_LIF_DUPLICATE_OR_INVALID' in assess_lif_failover([lif()],[lif(),lif()])['blockers']
    assert 'TARGET_LIF_SCHEMA_INVALID' in assess_lif_failover([lif()],[{}])['blockers']
