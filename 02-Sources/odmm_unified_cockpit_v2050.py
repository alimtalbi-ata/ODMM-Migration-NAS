"""ODMM V205.0 offline unified cockpit. No NAS writes or cutover. Auteur : Abdelhalim Talbi."""
import base64, hashlib, re
from odmm_campaign_portal_v2049 import CAMPAIGN_PAGE

PANEL='''<section id="unified-cockpit"><h2>Cockpit unifié · Migration NAS</h2><p class="muted">Source / cible · moteur natif · fidélité · qualification. Les observations restent locales au navigateur.</p><div class="cards"><div class="card">Source<strong id="src-device">Non renseignée</strong><span class="muted">Inventaire déclaratif</span></div><div class="card">Cible<strong id="dst-device">Non renseignée</strong><span class="muted">Inventaire déclaratif</span></div><div class="card">Transfert<strong id="transfer-status">NO_EVIDENCE</strong><span class="muted">Aucune preuve de copie</span></div><div class="card">ACL<strong id="acl-status">UNVERIFIED</strong><span class="muted">Preuves indépendantes requises</span></div></div><label for="unified-file">Importer un rapport de campagne ODMM (JSON local)</label> <input type="file" id="unified-file" accept=".json,application/json"><p id="unified-result" role="status" aria-live="polite" class="warn">NO_EVIDENCE · Cutover interdit</p><table><thead><tr><th>Contrôle</th><th>État</th><th>Interprétation</th></tr></thead><tbody id="unified-checks"><tr><td>Intégrité</td><td>UNVERIFIED</td><td>Comparer les empreintes source/cible</td></tr><tr><td>ACL et identités</td><td>UNVERIFIED</td><td>Collecte indépendante et accès effectif</td></tr><tr><td>Cutover</td><td>BLOCKED</td><td>Validation humaine et qualification réelle requises</td></tr></tbody></table></section>'''
SCRIPT='''<script>
'use strict';document.getElementById('unified-file').addEventListener('change',async function(){
const result=document.getElementById('unified-result'),checks=document.getElementById('unified-checks');
result.textContent='Rapport non qualifié · Cutover interdit';checks.replaceChildren();
for(const id of ['src-device','dst-device'])document.getElementById(id).textContent='Non renseignée';
document.getElementById('transfer-status').textContent='NO_EVIDENCE';document.getElementById('acl-status').textContent='UNVERIFIED';
try{const file=this.files[0];if(!file)throw Error('Aucun fichier');if(file.size>1048576)throw Error('Rapport trop volumineux');
const r=JSON.parse(await file.text());if(!r||r.schema!=='odmm.campaign_report.v2049'||typeof r.campaign_id!=='string'||r.campaign_id.length>256||!Number.isInteger(r.assessments)||r.assessments<0||!['MATCH','MISMATCH','UNVERIFIED','NO_EVIDENCE'].includes(r.latest_status)||r.cutover_authorized!==false||r.validation_authorized!==false||!Number.isInteger(r.total_mismatches)||r.total_mismatches<0||!Number.isInteger(r.total_unverified)||r.total_unverified<0)throw Error('Schéma ou preuves invalides');
result.textContent='Campagne '+r.campaign_id+' · '+r.latest_status+' · Cutover interdit';
for(const [a,b,c] of [['Registre',r.latest_status,'Évaluations : '+r.assessments],['Écarts',String(r.total_mismatches),'Écarts constatés dans les évaluations'],['ACL / identités','UNVERIFIED','Aucune certification NAS effective'],['Transfert','NO_EVIDENCE','Le rapport de fidélité ne prouve pas une exécution du moteur'],['Cutover','BLOCKED','Aucune bascule automatique']]){const tr=document.createElement('tr');for(const value of [a,b,c]){const td=document.createElement('td');td.textContent=value;tr.appendChild(td)}checks.appendChild(tr)}
}catch(e){result.textContent='Import refusé : '+e.message+' · Cutover interdit'}
});
</script>'''
PAGE=CAMPAIGN_PAGE.replace('</main>',PANEL+'</main>').replace('</body>',SCRIPT+'</body>').replace('V204.9','V205.0').replace('V5.5.9','V5.6.0')

def cockpit_csp():
    entries=[]
    for tag in ('script','style'):
        for body in re.findall(r'<'+tag+r'>(.*?)</'+tag+r'>',PAGE,re.S):
            entries.append((tag,"'sha256-"+base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()+"'"))
    return "default-src 'none'; script-src "+' '.join(v for k,v in entries if k=='script')+'; style-src '+' '.join(v for k,v in entries if k=='style')+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

def attach_unified_cockpit(app,*,authorize):
    if not callable(authorize):raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    from fastapi import Request,HTTPException
    from fastapi.responses import HTMLResponse
    async def page(request:Request):
        if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        return HTMLResponse(PAGE,headers={'Content-Security-Policy':cockpit_csp(),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    app.add_api_route('/qualification/cockpit',page,methods=['GET'],include_in_schema=False)
