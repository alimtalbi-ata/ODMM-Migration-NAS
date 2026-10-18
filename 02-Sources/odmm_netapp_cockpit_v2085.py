"""Authenticated read-only NetApp ACL/NFS differences dashboard extension.
Server-controlled evidence only. Author: Abdelhalim Talbi.
"""
import html
from odmm_netapp_policy_v2084 import compare_nfs_policies
from odmm_netapp_access_v2082 import assess_access_evidence

def assess_differences(source_policy,target_policy,source_tests,target_tests,identity_mappings,*,snapmirror=None,source_fidelity=None,target_fidelity=None,source_recipe=None,target_recipe=None,trusted_collectors=None):
    policy=compare_nfs_policies(source_policy,target_policy)
    access=assess_access_evidence(source_tests,target_tests,identity_mappings,snapmirror=snapmirror)
    fidelity=None
    if source_fidelity is not None or target_fidelity is not None:
        from odmm_netapp_fidelity_v2087 import assess_fidelity
        fidelity=assess_fidelity(source_fidelity,target_fidelity,identity_mappings)
    recipe=None
    if source_recipe is not None or target_recipe is not None:
        from odmm_netapp_evidence_v2088 import assess_recipe
        recipe=assess_recipe(source_recipe,target_recipe,identity_mappings,trusted_collectors=trusted_collectors or set())
    return {'schema':'odmm.netapp.cockpit.v2088','status':'BLOCKED','cutover_authorized':False,
            'blockers':sorted(set(policy['blockers']+access['blockers']+(fidelity['blockers'] if fidelity else [])+(recipe['blockers'] if recipe else []))),
            'fidelity_differences':fidelity['differences'] if fidelity else [],'fidelity_proofs_compared':fidelity['proofs_compared'] if fidelity else 0,
            'recipe_differences':recipe['differences'] if recipe else [],'recipe_pairs':recipe['pairs'] if recipe else [],'policy_differences':policy['differences'],'access_differences':access['differences'],
            'samples_compared':access['samples_compared'],'warnings':access['warnings']}

def render_differences(result):
    e=lambda v:html.escape(str(v),quote=True)
    rows=''.join('<tr><td>'+e(d.get('protocol','NFS'))+'</td><td>'+e(d.get('path',d.get('domain','—')))+'</td><td>'+e(d.get('operation',d.get('issue','—')))+'</td><td>'+e(d.get('source_allowed','—'))+'</td><td>'+e(d.get('target_allowed','—'))+'</td></tr>' for d in result.get('access_differences',[])+result.get('policy_differences',[])+result.get('recipe_differences',[]))
    rows+=''.join('<tr><td>'+e(d['acl_kind'])+'</td><td>'+e(d['path'])+'</td><td>'+e(d['field'])+'</td><td>'+e(d['source_digest'][:16])+'</td><td>'+e(d['target_digest'][:16])+'</td></tr>' for d in result.get('fidelity_differences',[]))
    blocks=''.join('<li>'+e(b)+'</li>' for b in result.get('blockers',[]))
    return ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM — NetApp écarts</title>'
            '<style>body{font:15px system-ui;background:#eef3f9;color:#18324b;margin:2rem}main{max-width:1200px;margin:auto;background:white;padding:2rem;border-radius:16px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #cbd5e1;text-align:left;padding:.65rem}th{background:#dbeafe}.alert{color:#a11928;font-weight:700}</style>'
            '<main><h1>ODMM · NetApp ONTAP</h1><p class="alert">BASCULE INTERDITE — preuves non qualifiées</p>'
            '<p>Échantillons comparés : '+e(result.get('samples_compared',0))+'</p><h2>Écarts source / cible</h2>'
            '<table><thead><tr><th>Protocole</th><th>Chemin / domaine</th><th>Opération / écart</th><th>Source</th><th>Cible</th></tr></thead><tbody>'+rows+'</tbody></table>'
            '<h2>Blocages</h2><ul>'+blocks+'</ul><p>Preuves serveur en lecture seule ; les tests simulés ne valent pas qualification sur ONTAP réel.</p></main></html>')

def attach_netapp_differences(app,*,authorize,get_evidence):
    """get_evidence returns a trusted server-side dict of arguments for assess_differences."""
    if not callable(authorize) or not callable(get_evidence):raise ValueError('AUTH_AND_PROVIDER_REQUIRED')
    from fastapi import Request,HTTPException
    from fastapi.responses import HTMLResponse,JSONResponse
    async def resolve(request:Request):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        try:
            evidence=get_evidence()
            if not isinstance(evidence,dict):raise ValueError('INVALID_EVIDENCE')
            return assess_differences(**evidence)
        except Exception:raise HTTPException(503,'NETAPP_EVIDENCE_UNAVAILABLE')
    async def api(request:Request):
        return JSONResponse(await resolve(request),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request):
        return HTMLResponse(render_differences(await resolve(request)),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none';style-src 'unsafe-inline';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/differences',api,methods=['GET'])
    app.add_api_route('/operations/netapp/differences',page,methods=['GET'],include_in_schema=False)
