"""ODMM V210.4: fail-closed, read-only Vault HA observability. Author: Abdelhalim Talbi."""
from html import escape

METRICS = ('requests', 'successes', 'failures', 'failovers', 'circuit_rejections')

def assess_vault_ha(ha_client, *, failure_rate_warning=0.10, min_requests=10):
    """Evaluate a snapshot without accessing credentials or mutating HA state."""
    result = {'schema':'odmm.vault.ha.operations.v2104', 'state':'UNKNOWN',
              'severity':'CRITICAL', 'alerts':['VAULT_TELEMETRY_UNAVAILABLE'],
              'metrics':{}, 'configured_endpoints':0, 'available_endpoints':0,
              'cutover_authorized':False, 'status':'BLOCKED'}
    try:
        if type(failure_rate_warning) not in (int,float) or not 0 <= failure_rate_warning <= 1:
            raise ValueError('INVALID_THRESHOLD')
        if type(min_requests) is not int or min_requests < 1:
            raise ValueError('INVALID_THRESHOLD')
        snapshot = ha_client.status()
        if not isinstance(snapshot,dict) or snapshot.get('schema') != 'odmm.vault.ha.v2103':
            raise ValueError('INVALID_SNAPSHOT')
        n,a = snapshot['configured_endpoints'],snapshot['available_endpoints']
        metrics = snapshot['metrics']
        if type(n) is not int or not 1 <= n <= 8 or type(a) is not int or not 0 <= a <= n:
            raise ValueError('INVALID_SNAPSHOT')
        if not isinstance(metrics,dict) or any(type(metrics.get(k)) is not int or metrics[k]<0 for k in METRICS):
            raise ValueError('INVALID_SNAPSHOT')
        if metrics['successes'] + metrics['circuit_rejections'] > metrics['requests']:
            raise ValueError('INVALID_SNAPSHOT')
        if snapshot.get('state') != ('AVAILABLE' if a else 'UNAVAILABLE'):
            raise ValueError('INVALID_SNAPSHOT')
        alerts=[]
        if not a: alerts.append('VAULT_ALL_ENDPOINTS_UNAVAILABLE')
        elif a<n: alerts.append('VAULT_HA_DEGRADED')
        if metrics['circuit_rejections']: alerts.append('VAULT_CIRCUIT_REJECTIONS')
        attempts=metrics['successes']+metrics['failures']
        if attempts >= min_requests and metrics['failures']/attempts >= failure_rate_warning:
            alerts.append('VAULT_FAILURE_RATE_HIGH')
        result.update(state=snapshot['state'],severity='CRITICAL' if not a else 'WARNING' if alerts else 'OK',
                      alerts=alerts,metrics={k:metrics[k] for k in METRICS},
                      configured_endpoints=n,available_endpoints=a)
    except Exception:
        pass
    return result

def create_vault_ha_operations_app(*, ha_client, **kwargs):
    """Append authenticated GET-only Vault HA telemetry to the existing Operations app."""
    from fastapi import Request, HTTPException
    from fastapi.responses import JSONResponse, HTMLResponse
    from odmm_vault_readiness_v2100 import create_vault_operations_app
    from odmm_operations_security import make_request_authorizer
    app=create_vault_operations_app(**kwargs)
    authorize=make_request_authorizer(kwargs['resolve_verified_principal'])
    def evaluate(request):
        try:
            if authorize(request) is not True: raise HTTPException(403,'FORBIDDEN')
        except HTTPException: raise
        except Exception: raise HTTPException(403,'FORBIDDEN')
        return assess_vault_ha(ha_client)
    async def api(request:Request):
        return JSONResponse(evaluate(request),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request):
        data=evaluate(request)
        alerts=''.join('<li>'+escape(a)+'</li>' for a in data['alerts']) or '<li>Aucune alerte</li>'
        body=('<html lang="fr"><meta charset="utf-8"><title>ODMM Vault HA</title><main>'
              '<h1>Vault HA — Operations</h1><strong>Cutover non autorisé</strong>'
              '<p>État : '+escape(data['state'])+'</p><p>Sévérité : '+escape(data['severity'])+'</p>'
              '<p>Points disponibles : '+str(data['available_endpoints'])+' / '+str(data['configured_endpoints'])+'</p>'
              '<h2>Alertes</h2><ul>'+alerts+'</ul></main></html>')
        return HTMLResponse(body,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/vault/ha-health',api,methods=['GET'])
    app.add_api_route('/operations/vault/ha-health',page,methods=['GET'],include_in_schema=False)
    return app
