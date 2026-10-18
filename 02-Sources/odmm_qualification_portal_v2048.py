"""Authenticated, read-only offline qualification cockpit. Auteur : Abdelhalim Talbi."""
import base64
import hashlib
import re
from html import escape

PAGE = '''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ODMM · Qualification NAS</title><style>
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#081323;color:#eef5ff}*{box-sizing:border-box}body{margin:0}header{padding:25px 5%;background:#10263d;border-bottom:1px solid #335673}h1{margin:0;font-size:27px}header p,.muted{color:#a6bfd2}main{max-width:1260px;margin:24px auto;padding:0 18px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}.card,section{background:#132a42;border:1px solid #345572;border-radius:14px;padding:21px;margin-bottom:17px}.card strong{display:block;font-size:27px;color:#7ed5e7}.chip{border:1px solid #9c8154;color:#ffd49b;padding:6px 12px;border-radius:24px;display:inline-block}textarea{display:block;width:100%;min-height:180px;background:#071729;color:#f3f7fc;border:1px solid #5a809d;border-radius:8px;padding:14px;font:13px monospace}button{background:#27acc4;border:0;color:#071725;padding:11px 18px;border-radius:8px;font-weight:700;cursor:pointer;margin:12px 0}button:focus-visible{outline:3px solid #ffe291}table{border-collapse:collapse;width:100%}td,th{padding:12px;border-bottom:1px solid #355573;text-align:left}th{color:#a8c9db}#result{white-space:pre-wrap;overflow-wrap:anywhere}.warn{color:#ffd49b}.ok{color:#86e4bc}footer{padding:24px;color:#a9c4d6}
</style></head><body><header><h1>ODMM · Qualification source / cible</h1><p>V204.8 · Inspection locale d'exports constructeur · Auteur : Abdelhalim Talbi</p></header><main><div class="cards"><div class="card">Mode<strong>Lecture seule</strong><span class="muted">Aucune écriture sur les NAS</span></div><div class="card">Constructeurs<strong>3 adaptateurs</strong><span class="muted">ONTAP · PowerScale · TrueNAS</span></div><div class="card">Cutover<strong>Interdit</strong><span class="muted">Aucune certification automatique</span></div></div><section><h2>Importer un export JSON anonymisé</h2><p class="muted">Collez une observation hors ligne. L'analyse s'exécute uniquement dans le navigateur ; aucune donnée n'est transmise au serveur.</p><label for="payload">Observation constructeur</label><textarea id="payload" spellcheck="false">{"vendor":"netapp_ontap","observed":{"model":"FAS","software_version":"9.x","protocol":"NFS","security_style":"unix"}}</textarea><button id="inspect" type="button">Analyser l'export</button><div id="result" role="status" aria-live="polite" class="warn">En attente d'analyse · aucune preuve de conformité</div></section><section><h2>Qualification par propriété</h2><table><thead><tr><th>Propriété</th><th>État</th><th>Preuve nécessaire</th></tr></thead><tbody id="checks"><tr><td>ACL NFSv4 / SMB</td><td>UNVERIFIED</td><td>Collecte et comparaison source/cible</td></tr><tr><td>UID / GID / SID</td><td>UNVERIFIED</td><td>Mapping et accès effectif</td></tr><tr><td>Attributs / ADS</td><td>UNVERIFIED</td><td>Inventaire et test de restauration</td></tr></tbody></table></section><section><h2>État du système</h2><p class="warn">Ce cockpit ne prouve ni la configuration active d'un NAS ni la fidélité d'une migration. L'API de migration existante n'est pas modifiée.</p></section><footer>ODMM V204.8 · Compact V5.5.8 · Auteur : Abdelhalim Talbi</footer></main><script>
'use strict';const $=id=>document.getElementById(id);const vendors=['netapp_ontap','dell_powerscale','truenas_scale'];$('inspect').addEventListener('click',()=>{let data;try{if($('payload').value.length>1048576)throw Error('Export trop volumineux');data=JSON.parse($('payload').value);if(!data||typeof data!=='object'||Array.isArray(data)||!vendors.includes(data.vendor)||!data.observed||typeof data.observed!=='object'||Array.isArray(data.observed))throw Error('Schéma ou constructeur non reconnu');let keys=Object.keys(data.observed).filter(k=>typeof data.observed[k]==='string'&&data.observed[k].trim());$('result').textContent='Statut : UNVERIFIED | Cutover : INTERDIT\\nConstructeur : '+data.vendor+'\\nChamps déclarés : '+(keys.join(', ')||'aucun')+'\\nPreuves ACL, identités et données : NON FOURNIES';}catch(e){$('result').textContent='Export refusé : '+e.message+' | Cutover : INTERDIT';}});
</script></body></html>'''

def csp():
    hashes=[]
    for tag in ('script','style'):
        body=re.search(r'<'+tag+r'>(.*?)</'+tag+r'>',PAGE,re.S).group(1)
        hashes.append("'sha256-"+base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()+"'")
    return "default-src 'none'; script-src "+hashes[0]+"; style-src "+hashes[1]+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

def attach_qualification_portal(app, *, authorize):
    if not callable(authorize):raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    if not hasattr(app,'add_api_route'):raise ValueError('FASTAPI_APP_REQUIRED')
    from fastapi import HTTPException, Request
    from fastapi.responses import HTMLResponse
    async def cockpit(request:Request):
        if authorize(request) is not True:raise HTTPException(status_code=403,detail='FORBIDDEN')
        return HTMLResponse(PAGE,headers={'Content-Security-Policy':csp(),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})
    app.add_api_route('/qualification',cockpit,methods=['GET'],include_in_schema=False)
    return cockpit
