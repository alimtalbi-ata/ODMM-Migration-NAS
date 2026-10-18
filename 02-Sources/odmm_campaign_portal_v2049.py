"""Offline campaign evidence dashboard; local browser parsing, no upload."""
from odmm_qualification_portal_v2048 import PAGE, csp
from html import escape
import base64,hashlib,re

ADD='''<section id="campaign-panel"><h2>Campagne · registre de fidélité</h2><p class="muted">Chargez un rapport JSON exporté depuis le registre local. Lecture dans ce navigateur uniquement.</p><label for="campaign-file">Rapport de campagne</label> <input id="campaign-file" type="file" accept="application/json,.json"><div id="campaign-result" role="status" aria-live="polite" class="warn">Aucune preuve de campagne chargée · Cutover interdit</div><table><thead><tr><th>Indicateur</th><th>Valeur</th></tr></thead><tbody id="campaign-table"><tr><td>État</td><td>NO_EVIDENCE</td></tr></tbody></table></section>'''
JS='''<script>
'use strict';document.getElementById('campaign-file').addEventListener('change',async function(){
const status=document.getElementById('campaign-result'),table=document.getElementById('campaign-table');
status.textContent='Rapport non qualifié · Cutover interdit';table.replaceChildren();
try{const f=this.files[0];if(!f)throw Error('Aucun fichier');if(f.size>1048576)throw Error('Rapport trop volumineux');
const r=JSON.parse(await f.text());if(!r||r.schema!=='odmm.campaign_report.v2049'||typeof r.campaign_id!=='string'||!Number.isInteger(r.assessments)||r.assessments<0||!['MATCH','MISMATCH','UNVERIFIED','NO_EVIDENCE'].includes(r.latest_status)||r.cutover_authorized!==false||r.validation_authorized!==false)throw Error('Schéma de rapport invalide');
status.textContent='Campagne : '+r.campaign_id+' | '+r.latest_status+' | Cutover interdit';
for(const [k,v] of [['Campagne',r.campaign_id],['Évaluations',r.assessments],['Dernier état',r.latest_status],['Écarts',r.total_mismatches],['Non vérifiés',r.total_unverified],['Cutover','INTERDIT']]){const tr=document.createElement('tr');for(const value of [k,String(v)]){const td=document.createElement('td');td.textContent=value;tr.appendChild(td)}table.appendChild(tr)}
}catch(e){status.textContent='Rapport refusé : '+e.message+' | Cutover interdit'}
});
</script>'''
CAMPAIGN_PAGE=PAGE.replace('</main>',ADD+'</main>').replace('</body>',JS+'</body>').replace('V204.8','V204.9').replace('V5.5.8','V5.5.9')

def campaign_csp():
    hashes=[]
    for tag in ('script','style'):
        for body in re.findall(r'<'+tag+r'>(.*?)</'+tag+r'>',CAMPAIGN_PAGE,re.S):
            hashes.append((tag,"'sha256-"+base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()+"'"))
    return "default-src 'none'; script-src "+' '.join(v for k,v in hashes if k=='script')+'; style-src '+' '.join(v for k,v in hashes if k=='style')+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

def attach_campaign_portal(app,*,authorize):
    if not callable(authorize):raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    from fastapi import Request,HTTPException
    from fastapi.responses import HTMLResponse
    async def page(request:Request):
        if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        return HTMLResponse(CAMPAIGN_PAGE,headers={'Content-Security-Policy':campaign_csp(),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    app.add_api_route('/qualification/campaign',page,methods=['GET'],include_in_schema=False)
