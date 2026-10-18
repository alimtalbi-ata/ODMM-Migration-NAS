"""V196.8: self-contained read-only operations cockpit; uses the V196.7 API.

No separate data access path, no CDN, no mutation controls. Deployment must
provide its own authenticated session, HTTPS, and authorization callback.
"""
import hashlib
import base64
import re

PAGE = '''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ODMM | Operations</title><style>
:root{color-scheme:dark;font:15px system-ui,Arial,sans-serif;background:#0a1424;color:#ecf3ff}*{box-sizing:border-box}body{margin:0}header{padding:24px 32px;background:#10253d;border-bottom:1px solid #30516a}h1{margin:0;font-size:25px}header p{color:#a6c4da;margin:8px 0 0}main{max-width:1300px;margin:auto;padding:26px}section{margin:18px 0;padding:22px;border:1px solid #31516c;border-radius:14px;background:#12263d}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.metric{background:#1b3954;padding:16px;border-radius:10px}.metric strong{display:block;font-size:27px;margin-top:8px}.subtle{color:#a8c4d8}button{background:#1c9cb5;color:#001b26;border:0;border-radius:8px;padding:10px 15px;cursor:pointer;font-weight:700}button:focus-visible,a:focus-visible{outline:3px solid #ffe285}button:disabled{opacity:.5;cursor:not-allowed}table{border-collapse:collapse;width:100%;min-width:600px}th,td{text-align:left;border-bottom:1px solid #31516c;padding:12px;overflow-wrap:anywhere}th{color:#a6c4da}tr:hover{background:#1c3951}.scroll{overflow:auto}#notice{min-height:24px;color:#ffd29e}.tag{border:1px solid #5e859e;border-radius:12px;padding:3px 9px}footer{color:#a6c4da;padding:18px 0} .toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
</style></head><body><header><h1>ODMM · Console des opérations</h1><p>Consultation sécurisée du registre · aucune action destructive · Auteur : Abdelhalim Talbi</p></header><main><div class="toolbar"><span class="tag">Lecture seule</span><button id="refresh" type="button">Actualiser</button></div><p id="notice" role="status" aria-live="polite"></p><section id="netapp-panel"><h2>NetApp ONTAP · préqualification</h2><p class="subtle">Écarts source/cible et inventaire. Lecture seule, bascule non autorisée.</p><p><a href="/operations/netapp">Inventaire et préqualification</a> · <a href="/operations/netapp/differences">Écarts ACL / NFS</a></p></section><section id="nas-panel"><h2>Audit NAS · ONTAP / FlashBlade / PowerScale</h2><p class="subtle">Comparaison en lecture seule · bascule interdite.</p><p><a href="/operations/nas-pairs">Directions NAS</a> · <a href="/operations/nas-access">Audit ACL</a> · <a href="/operations/nas-provenance">Provenance et fraîcheur</a> · <a href="/operations/nas-acl-audit">ACL NFSv4 / SMB3</a> · <a href="/api/v1/operations/nas-acl-audit/export">Export ACL signé</a> · <a href="/api/v1/operations/nas-consistency/export">Exporter la cohérence (JSON)</a></p></section><section id="qualification-history-panel"><h2>Qualification Windows · Historique</h2><p class="subtle">Recettes navigateur, anomalies et comparaison des exécutions. Consultation uniquement.</p><p><a href="/operations/qualification-history">Historique des recettes</a> · <a href="/api/v1/operations/qualification-history">Export JSON</a></p></section><section id="campaign-audit-panel"><h2>Campagnes multi-identités · Audit LDAP</h2><p class="subtle">Historique ancré, écarts par identité et export JSON. Lecture seule, cutover interdit.</p><p><a href="/operations/campaign-audit">Consulter les campagnes</a> · <a href="/api/v1/operations/campaign-audit/export">Exporter les preuves (JSON)</a></p></section><section id="oidc-panel"><h2>Identité OIDC · supervision</h2><p class="subtle">Disponibilité du fournisseur d’identité uniquement — ne représente pas l’état du moteur de migration.</p><div id="oidc-metrics" class="metrics"></div><div id="oidc-events" class="subtle" role="status">Chargement…</div><label for="oidc-filter">Filtrer les événements</label> <select id="oidc-filter"><option value="ALL">Tous</option><option value="OIDC_DEGRADED">Dégradation</option><option value="OIDC_OUTAGE">Indisponibilité</option><option value="OIDC_RECOVERED">Rétablissement</option></select><div class="scroll"><table><thead><tr><th>Horodatage</th><th>Événement</th><th>Transition</th></tr></thead><tbody id="oidc-timeline"></tbody></table></div></section><section><h2>Vue d’ensemble</h2><div id="metrics" class="metrics"><span class="subtle">Chargement…</span></div><p id="audit" class="subtle"></p></section><section><div class="toolbar"><h2>Migrations</h2><span class="subtle">Dernières 50 migrations</span></div><div class="scroll"><table><thead><tr><th>Identifiant</th><th>Source</th><th>Cible</th><th>État</th><th>Création</th><th>Opérations</th></tr></thead><tbody id="jobs"></tbody></table></div></section><section><h2 id="ops-title">Chronologie des opérations</h2><div class="scroll"><table><thead><tr><th>ID</th><th>État</th><th>Propriétaire</th><th>Epoch</th><th>Expiration du bail</th><th>Dernière modification</th></tr></thead><tbody id="operations"><tr><td colspan="6">Sélectionnez une migration.</td></tr></tbody></table></div></section><footer>ODMM V197.5 · Compact V4.8.5 · Les informations proviennent de l’API commune V196.7.</footer></main><script>
'use strict';
const base='/api/v1/operations';
const $=id=>document.getElementById(id);
function cell(row,value){const td=document.createElement('td');td.textContent=value==null?'—':String(value);row.appendChild(td);return td;}
function clear(id){$(id).replaceChildren();}
function status(msg){$('notice').textContent=msg;}
async function get(path){const res=await fetch(base+path,{credentials:'same-origin',headers:{'Accept':'application/json'},cache:'no-store'});if(!res.ok)throw new Error('API '+res.status);return await res.json();}
function metric(name,value){const box=document.createElement('div');box.className='metric';const label=document.createElement('span');label.textContent=name;const num=document.createElement('strong');num.textContent=String(value);box.append(label,num);$('metrics').appendChild(box);}
async function showOperations(id){clear('operations');$('ops-title').textContent='Opérations de '+id;try{const result=await get('/jobs/'+encodeURIComponent(id)+'/operations?limit=100');for(const op of result.items){const tr=document.createElement('tr');for(const k of ['id','state','owner','epoch','lease_until','updated_at'])cell(tr,op[k]);$('operations').appendChild(tr);}if(!result.items.length){const tr=document.createElement('tr');cell(tr,'Aucune opération');$('operations').appendChild(tr);}}catch(e){status('Lecture des opérations impossible : '+e.message);}}
async function refresh(){status('Chargement des données…');$('refresh').disabled=true;try{const [overview,jobs]=await Promise.all([get('/overview'),get('/jobs?limit=50')]);clear('metrics');metric('Migrations',overview.jobs);for(const [state,count] of Object.entries(overview.operations))metric(state,count);$('audit').textContent=overview.audit_head?'Dernière preuve d’audit : #'+overview.audit_head.seq+' · '+overview.audit_head.hash:'Aucune preuve d’audit';clear('jobs');for(const job of jobs.items){const tr=document.createElement('tr');for(const k of ['id','source','target','state','created_at'])cell(tr,job[k]);const td=document.createElement('td');const btn=document.createElement('button');btn.type='button';btn.textContent='Consulter';btn.addEventListener('click',()=>showOperations(job.id));td.appendChild(btn);tr.appendChild(td);$('jobs').appendChild(tr);}status('Données actualisées.');}catch(e){status('Accès indisponible : '+e.message);}finally{$('refresh').disabled=false;}}
async function refreshOIDC(){const box=$('oidc-metrics');box.replaceChildren();const events=$('oidc-events');try{const res=await fetch('/api/v1/operations/oidc-health',{credentials:'same-origin',headers:{Accept:'application/json'},cache:'no-store'});if(!res.ok)throw Error('HTTP '+res.status);const data=await res.json();const latest=data.observations?.[0];for(const [name,value] of [['État fournisseur',latest?.state??'INCONNU'],['Contrôles conservés',data.count??0],['Latence (ms)',latest?.latency_ms??'—']]){const el=document.createElement('div');el.className='metric';const label=document.createElement('span');label.textContent=name;const val=document.createElement('strong');val.textContent=String(value);el.append(label,val);box.append(el);}events.textContent='Historique OIDC local · moteur de migration : non mesuré';await refreshOIDCEvents();}catch(e){events.textContent='Historique OIDC indisponible ('+e.message+'). Aucune conclusion sur les migrations.';}}
async function refreshOIDCEvents(){const target=$('oidc-timeline');target.replaceChildren();try{const res=await fetch('/api/v1/operations/oidc-events?limit=100',{credentials:'same-origin',headers:{Accept:'application/json'},cache:'no-store'});if(!res.ok)throw Error('HTTP '+res.status);const data=await res.json();const filter=$('oidc-filter').value;for(const item of data.events){if(filter!=='ALL'&&item.event!==filter)continue;const tr=document.createElement('tr');cell(tr,item.observed_utc);cell(tr,item.event);cell(tr,(item.previous_state??'—')+' → '+item.current_state);target.appendChild(tr);}if(!target.children.length){const tr=document.createElement('tr');cell(tr,'Aucun événement correspondant');target.appendChild(tr);}}catch(e){const tr=document.createElement('tr');cell(tr,'Chronologie indisponible : '+e.message);target.appendChild(tr);}}
$('oidc-filter').addEventListener('change',refreshOIDCEvents);
$('refresh').addEventListener('click',()=>{refresh();refreshOIDC();});refresh();refreshOIDC();
</script></body></html>'''

def _csp():
    js = re.search(r"<script>(.*?)</script>", PAGE, re.S).group(1)
    css = re.search(r"<style>(.*?)</style>", PAGE, re.S).group(1)
    digest = lambda v: base64.b64encode(hashlib.sha256(v.encode()).digest()).decode()
    return "default-src 'none'; script-src 'sha256-" + digest(js) + "'; style-src 'sha256-" + digest(css) + "'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

def attach_operations_portal(app, *, authorize, oidc_history_db=None):
    """Install UI only; attach_readonly_routes must be installed separately.

    The authorization callback is required for both the UI and API routes.
    """
    if not callable(authorize):
        raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    if not hasattr(app, 'add_api_route'):
        raise ValueError('FASTAPI_APP_REQUIRED')
    from fastapi import HTTPException, Request
    from fastapi.responses import HTMLResponse

    async def cockpit(request: Request):
        if authorize(request) is not True:
            raise HTTPException(status_code=403, detail='FORBIDDEN')
        return HTMLResponse(PAGE, headers={
            'Content-Security-Policy': _csp(),
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
        })
    if oidc_history_db is not None:
        from odmm_oidc_health_history_v1995 import snapshot
        from pathlib import Path
        db_path = Path(oidc_history_db)
        async def oidc_health(request: Request):
            if authorize(request) is not True:
                raise HTTPException(status_code=403, detail='FORBIDDEN')
            if not db_path.is_file():
                raise HTTPException(status_code=503, detail='OIDC_HISTORY_UNAVAILABLE')
            try:
                result = snapshot(db_path, limit=50)
            except Exception:
                raise HTTPException(status_code=503, detail='OIDC_HISTORY_UNAVAILABLE')
            from fastapi.responses import JSONResponse
            return JSONResponse(result, headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
        async def oidc_events(request: Request, limit: int = 100):
            if authorize(request) is not True:
                raise HTTPException(status_code=403, detail='FORBIDDEN')
            if not 1 <= limit <= 1000:
                raise HTTPException(status_code=422, detail='INVALID_LIMIT')
            if not db_path.is_file():
                raise HTTPException(status_code=503, detail='OIDC_HISTORY_UNAVAILABLE')
            try:
                from odmm_oidc_alerts_v1997 import history
                events = history(db_path, limit=limit)
            except Exception:
                raise HTTPException(status_code=503, detail='OIDC_EVENTS_UNAVAILABLE')
            from fastapi.responses import JSONResponse
            return JSONResponse({'events': events, 'count': len(events), 'migration_engine_status': 'NOT_MEASURED', 'author': 'Abdelhalim Talbi'}, headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
        app.add_api_route('/api/v1/operations/oidc-events', oidc_events, methods=['GET'], include_in_schema=False)
        app.add_api_route('/api/v1/operations/oidc-health', oidc_health, methods=['GET'], include_in_schema=False)
    app.add_api_route('/operations', cockpit, methods=['GET'], include_in_schema=False)
    return cockpit
