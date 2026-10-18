"""Session controls for ODMM cockpit, without introducing new credentials. Auteur: Abdelhalim Talbi."""
import re,base64,hashlib
from odmm_cockpit_collection_v2060 import PAGE as BASE

PANEL='''<section id="session-v2066" aria-labelledby="session-title"><h2 id="session-title">Sécurité de session · V206.6</h2><p class="muted">Renouvellement et déconnexion HTTPS. La session doit déjà être établie par le serveur. Aucune opération de migration n'est autorisée ici.</p><div class="cards"><div class="card">Session<strong id="session-status">NON VÉRIFIÉE</strong></div><div class="card">Sécurité<strong>HTTPS · CSRF</strong></div><div class="card">Cutover<strong>INTERDIT</strong></div></div><button id="session-rotate" type="button">Renouveler ma session</button> <button id="session-logout" type="button">Se déconnecter</button><p id="session-feedback" role="status" aria-live="polite">Aucune action demandée.</p></section>'''
SCRIPT='''<script>
'use strict';(()=>{const byId=id=>document.getElementById(id);const csrf=()=>{const value=document.cookie.split(';').map(v=>v.trim()).find(v=>v.startsWith('odmm_csrf='));return value?decodeURIComponent(value.slice(10)):''};let busy=false;async function action(kind){if(busy)return;busy=true;byId('session-rotate').disabled=true;byId('session-logout').disabled=true;byId('session-feedback').textContent='Traitement en cours…';try{const token=csrf();if(!token)throw Error('Jeton CSRF absent : reconnectez-vous');const response=await fetch('/api/v1/session/'+kind,{method:'POST',credentials:'same-origin',redirect:'error',headers:{'X-ODMM-CSRF':token,'Accept':'application/json'},cache:'no-store'});if(!response.ok)throw Error('Opération refusée (HTTP '+response.status+')');const data=await response.json();if((kind==='rotate'&&data.status!=='ROTATED')||(kind==='logout'&&data.status!=='LOGGED_OUT'))throw Error('Réponse serveur inattendue');byId('session-status').textContent=kind==='rotate'?'RENOUVELÉE':'DÉCONNECTÉE';byId('session-feedback').textContent=kind==='rotate'?'Session renouvelée. Ancien jeton révoqué.':'Déconnexion confirmée. Cookies effacés.'}catch(err){byId('session-status').textContent='À VÉRIFIER';byId('session-feedback').textContent=err.message+' · Aucun cutover autorisé'}finally{busy=false;byId('session-rotate').disabled=false;byId('session-logout').disabled=false}}byId('session-rotate').addEventListener('click',()=>action('rotate'));byId('session-logout').addEventListener('click',()=>action('logout'))})();
</script>'''
PAGE=BASE.replace('</main>',PANEL+'</main>').replace('</body>',SCRIPT+'</body>')

def cockpit_csp():
    tags=[(tag,body) for tag in ('script','style') for body in re.findall(r'<'+tag+r'>(.*?)</'+tag+r'>',PAGE,re.S)]
    def hashes(tag):return ' '.join("'sha256-"+base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()+"'" for t,body in tags if t==tag)
    return "default-src 'none'; connect-src 'self'; script-src "+hashes('script')+'; style-src '+hashes('style')+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

def attach_session_cockpit(app, *, authorize):
    if not callable(authorize):raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    if any(getattr(route,'path',None)=='/qualification/cockpit' for route in app.routes):raise ValueError('COCKPIT_ROUTE_CONFLICT')
    from fastapi import Request,HTTPException
    from fastapi.responses import HTMLResponse
    def page(request:Request):
        if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        return HTMLResponse(PAGE,headers={'Content-Security-Policy':cockpit_csp(),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    app.add_api_route('/qualification/cockpit',page,methods=['GET'],include_in_schema=False)
    return app
