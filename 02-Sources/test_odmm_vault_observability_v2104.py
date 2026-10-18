from odmm_vault_observability_v2104 import assess_vault_ha
class Fake:
    def __init__(self,a=2,n=2,metrics=None):
        self.a,self.n,self.metrics=a,n,metrics or {'requests':10,'successes':10,'failures':0,'failovers':0,'circuit_rejections':0}
    def status(self):
        return {'schema':'odmm.vault.ha.v2103','state':'AVAILABLE' if self.a else 'UNAVAILABLE',
                'available_endpoints':self.a,'configured_endpoints':self.n,'metrics':self.metrics}
def test_healthy():
    x=assess_vault_ha(Fake());assert x['severity']=='OK' and x['cutover_authorized'] is False
def test_degraded():
    assert 'VAULT_HA_DEGRADED' in assess_vault_ha(Fake(1))['alerts']
def test_outage():
    assert assess_vault_ha(Fake(0))['severity']=='CRITICAL'
def test_circuit():
    f=Fake();f.metrics['circuit_rejections']=1;f.metrics['successes']=9;assert 'VAULT_CIRCUIT_REJECTIONS' in assess_vault_ha(f)['alerts']
def test_failure_rate():
    f=Fake(metrics={'requests':10,'successes':8,'failures':2,'failovers':1,'circuit_rejections':0})
    assert 'VAULT_FAILURE_RATE_HIGH' in assess_vault_ha(f)['alerts']
def test_bad_metrics_fail_closed():
    f=Fake();f.metrics['requests']=-1;assert assess_vault_ha(f)['severity']=='CRITICAL'
def test_provider_exception():
    class Broken:
        def status(self): raise RuntimeError('sensitive token')
    assert 'sensitive' not in str(assess_vault_ha(Broken()))
def test_threshold_validation():
    assert assess_vault_ha(Fake(),failure_rate_warning=-1)['state']=='UNKNOWN'
