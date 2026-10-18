"""V205.2 cockpit: local mount evidence panel. Auteur: Abdelhalim Talbi."""
import base64, hashlib, re
from odmm_capability_cockpit_v2051 import PAGE as PREVIOUS
PANEL='''<section id="mount-v2052"><h2>Montages NFS / SMB · observations locales</h2><p class="muted">Charger un rapport JSON produit par le collecteur local V205.2. Ce rapport ne certifie ni le constructeur, ni les ACL, ni les accès effectifs.</p><label>Rapport montage JSON <input id="mount-file" type="file" accept=".json,application/json"></label><p id="mount-result" role="status" aria-live="polite">Aucun rapport · UNVERIFIED · Cutover interdit</p><table><thead><tr><th>Propriété</th><th>Observation</th></tr></thead><tbody id="mount-rows"></tbody></table></section>'''
SCRIPT='''<script>
'use strict';(()=>{const input=document.getElementById('mount-file'),result=document.getElementById('mount-result'),rows=document.getElementById('mount-rows');const fields=['filesystem','protocol_family','mount_readonly_declared','vendor','firmware','acl','identity_mapping','effective_access'];input.addEventListener('change',async()=>{rows.replaceChildren();result.textContent='UNVERIFIED · Cutover interdit';const file=input.files[0];if(!file)return;try{if(file.size>1048576)throw Error('Fichier supérieur à 1 Mio');const data=JSON.parse(await file.text());if(!data||data.schema!=='odmm.mount_probe.v2052'||data.evidence_type!=='LOCAL_MOUNT_METADATA'||data.status!=='UNVERIFIED'||data.cutover_authorized!==false||!['nfs','nfs4','cifs','smb3'].includes(data.filesystem)||!['NFS','SMB'].includes(data.protocol_family)||data.protocol_family!==(['cifs','smb3'].includes(data.filesystem)?'SMB':'NFS'))throw Error('Rapport non conforme');for(const key of fields){const value=data[key];if(typeof value!=='string'&&typeof value!=='boolean')throw Error('Champ invalide : '+key);if(typeof value==='string'&&value.length>256)throw Error('Champ trop long');const tr=document.createElement('tr');for(const v of [key,String(value)]){const td=document.createElement('td');td.textContent=v;tr.appendChild(td)}rows.appendChild(tr)}result.textContent='Montage local observé · ACL et identités UNVERIFIED · Cutover interdit'}catch(e){rows.replaceChildren();result.textContent='Import refusé : '+e.message+' · Cutover interdit'}})})();
</script>'''
PAGE=PREVIOUS.replace('</main>',PANEL+'</main>').replace('</body>',SCRIPT+'</body>').replace('V205.1','V205.2').replace('V5.6.1','V5.6.2')
def cockpit_csp():
 tags=[(tag,body) for tag in ('script','style') for body in re.findall(r'<'+tag+r'>(.*?)</'+tag+r'>',PAGE,re.S)]
 def hashes(tag):return ' '.join("'sha256-"+base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()+"'" for t,body in tags if t==tag)
 return "default-src 'none'; script-src "+hashes('script')+'; style-src '+hashes('style')+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
def attach_mount_cockpit(app,*,authorize):
 if not callable(authorize):raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
 from fastapi import Request,HTTPException
 from fastapi.responses import HTMLResponse
 async def page(request:Request):
  if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
  return HTMLResponse(PAGE,headers={'Content-Security-Policy':cockpit_csp(),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
 app.add_api_route('/qualification/cockpit',page,methods=['GET'],include_in_schema=False)
