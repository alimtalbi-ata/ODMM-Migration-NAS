"""ODMM V210.5 — authenticated, read-only Prometheus export. Author: Abdelhalim Talbi."""
from fastapi import Request, HTTPException
from fastapi.responses import PlainTextResponse
from odmm_operations_security import make_request_authorizer
from odmm_vault_observability_v2104 import assess_vault_ha, create_vault_ha_operations_app

METRICS = ('requests','successes','failures','failovers','circuit_rejections')
def render_prometheus(ha_client):
    data=assess_vault_ha(ha_client)
    # No endpoint addresses, token IDs, labels or other secrets are exported.
    lines=['# HELP odmm_vault_ha_available_endpoints Available Vault endpoints.',
           '# TYPE odmm_vault_ha_available_endpoints gauge',
           'odmm_vault_ha_available_endpoints '+str(data['available_endpoints']),
           '# HELP odmm_vault_ha_configured_endpoints Configured Vault endpoints.',
           '# TYPE odmm_vault_ha_configured_endpoints gauge',
           'odmm_vault_ha_configured_endpoints '+str(data['configured_endpoints']),
           '# HELP odmm_vault_ha_telemetry_valid Vault HA telemetry validation.',
           '# TYPE odmm_vault_ha_telemetry_valid gauge',
           'odmm_vault_ha_telemetry_valid '+('0' if data['state']=='UNKNOWN' else '1')]
    for metric in METRICS:
        lines.extend(('# TYPE odmm_vault_ha_'+metric+'_total counter',
                      'odmm_vault_ha_'+metric+'_total '+str(data['metrics'].get(metric,0))))
    return '\n'.join(lines)+'\n'

def create_vault_prometheus_operations_app(*,ha_client,**kwargs):
    app=create_vault_ha_operations_app(ha_client=ha_client,**kwargs)
    authorize=make_request_authorizer(kwargs['resolve_verified_principal'])
    async def metrics(request:Request):
        try:
            if authorize(request) is not True: raise HTTPException(403,'FORBIDDEN')
        except HTTPException: raise
        except Exception: raise HTTPException(403,'FORBIDDEN')
        return PlainTextResponse(render_prometheus(ha_client),media_type='text/plain; version=0.0.4; charset=utf-8',
                                 headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    app.add_api_route('/api/v1/operations/vault/ha-metrics',metrics,methods=['GET'])
    return app
