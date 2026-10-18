"""Self-contained interactive read-only campaign audit UI. Author: Abdelhalim Talbi."""
import html
import hashlib
import base64
import json
from odmm_access_audit_v2184 import AuditError
from odmm_campaign_dashboard_integrity_v2201 import validate_dashboard

def render_interactive(report):
    validate_dashboard(report)
    if report.get('schema') != 'odmm.campaign-dashboard.v2196' or report.get('cutover_authorized') is not False or report.get('anchored') is not True:
        raise AuditError('INVALID_DASHBOARD')
    esc=lambda x:html.escape(str(x),quote=True)
    rows=[]
    for case in report['cases']:
        if not isinstance(case.get('mismatch'),bool) or not isinstance(case.get('seq'),int):
            raise AuditError('INVALID_CASE')
        severity=("critical" if not case["local_access_equal"] else "warning" if not case["groups_equal"] else "ok")
        rows.append('<tr data-severity="'+severity+'" data-identity="'+esc(case['identity_ref'])+'" data-mismatch="'+str(case['mismatch']).lower()+'"><td>'+esc(case['seq'])+'</td><td>'+esc(case['case_id'])+'</td><td>'+esc(case['identity_ref'])+'</td><td>'+({'critical':'Critique · accès','warning':'Attention · groupes','ok':'Conforme'}[severity])+'</td><td>'+('Oui' if case['groups_equal'] else 'Non')+'</td><td>'+('Oui' if case['local_access_equal'] else 'Non')+'</td></tr>')
    timeline={}
    for c in report['cases']:
        t=timeline.setdefault(c['seq'],{'total':0,'mismatches':0});t['total']+=1;t['mismatches']+=int(c['mismatch'])
    bars=''.join('<div class="bar"><span>Audit '+esc(seq)+'</span><progress max="'+str(max(1,v['total']))+'" value="'+str(v['mismatches'])+'"></progress><span>'+str(v['mismatches'])+'/'+str(v['total'])+' écarts</span></div>' for seq,v in sorted(timeline.items()))
    return '''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ODMM — Campagnes</title><style>
body{font:15px system-ui;background:#f2f6fb;color:#14243b;margin:0}main{max-width:1200px;margin:auto;padding:28px}header{background:#123154;color:white;padding:20px 28px}h1{margin:0}.warning{background:#fff3dc;color:#843c08;padding:12px;border-radius:8px}.metrics{display:flex;gap:12px;flex-wrap:wrap}.metric{background:white;border-radius:10px;padding:18px;min-width:130px;box-shadow:0 1px 4px #ccd6e2}.metric strong{font-size:28px;display:block}.controls{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}input,select{padding:10px;border:1px solid #aabbd0;border-radius:6px}table{width:100%;border-collapse:collapse;background:white}th,td{padding:10px;text-align:left;border-bottom:1px solid #d9e2ee}th{background:#dce9f8}tr[data-mismatch="true"]{background:#fff5ec}tr[data-severity="critical"]{border-left:5px solid #b91c1c}tr[data-severity="warning"]{border-left:5px solid #d97706}tr[data-severity="ok"]{border-left:5px solid #15803d}tr[hidden]{display:none}input:focus-visible,select:focus-visible{outline:3px solid #2563eb;outline-offset:2px}.bar{display:flex;align-items:center;gap:12px;margin:10px 0}.bar progress{flex:1}small{overflow-wrap:anywhere}a{color:#124d85}
</style></head><body><header><h1>ODMM · Audit des campagnes</h1></header><main><p class="warning">Prévalidation locale uniquement · Cutover interdit · NAS non qualifié</p><section class="metrics"><div class="metric"><strong id="visible">'''+esc(report['case_count'])+'''</strong>Cas affichés</div><div class="metric"><strong id="diff">'''+esc(report['mismatch_count'])+'''</strong>Écarts affichés</div><div class="metric"><strong>'''+esc(report['entries'])+'''</strong>Entrées d'audit</div></section><div class="controls"><label>Identité <input id="identity" type="search" placeholder="Filtrer une identité"></label><label>Criticité <select id="severity"><option value="all">Toutes</option><option value="critical">Critique</option><option value="warning">Attention</option><option value="ok">Conforme</option></select></label><label>Résultat <select id="status"><option value="all">Tous</option><option value="true">Écarts</option><option value="false">Identiques</option></select></label></div><h2>Chronologie des audits</h2>'''+bars+'''<h2>Détail des identités</h2><p>Critique : accès local divergent · Attention : groupes divergents · Conforme : aucun écart.</p><table><thead><tr><th>Audit</th><th>Cas</th><th>Identité</th><th>Résultat</th><th>Groupes</th><th>Accès local</th></tr></thead><tbody id="cases">'''+''.join(rows)+'''</tbody></table><p id="empty" hidden>Aucun cas pour ces filtres.</p><p><a href="/api/v1/operations/campaign-audit/export">Exporter JSON vérifié</a></p><small>Ancrage vérifié · SHA-256 : '''+esc(report['audit_head'])+''' · Auteur : Abdelhalim Talbi</small></main><script>
(()=>{'use strict';const input=document.getElementById('identity'),status=document.getElementById('status'),severity=document.getElementById('severity'),rows=[...document.querySelectorAll('#cases tr')];function filter(){const q=input.value.toLocaleLowerCase(),s=status.value;let count=0,diff=0;for(const row of rows){const ok=row.dataset.identity.toLocaleLowerCase().includes(q)&&(s==='all'||row.dataset.mismatch===s)&&(severity.value==='all'||row.dataset.severity===severity.value);row.hidden=!ok;if(ok){count++;if(row.dataset.mismatch==='true')diff++;}}document.getElementById('visible').textContent=count;document.getElementById('diff').textContent=diff;document.getElementById('empty').hidden=count!==0;}input.addEventListener('input',filter);status.addEventListener('change',filter);severity.addEventListener('change',filter);})();
</script></body></html>'''

def csp_policy(page):
    """Return CSP matching the exact inline script, to enforce via HTTP response header."""
    if page.count('<script>') != 1 or page.count('</script>') != 1:
        raise AuditError('INVALID_SCRIPT_LAYOUT')
    script=page.split('<script>',1)[1].split('</script>',1)[0]
    digest=base64.b64encode(hashlib.sha256(script.encode('utf-8')).digest()).decode('ascii')
    return ("default-src 'none'; script-src 'sha256-"+digest+"'; style-src 'unsafe-inline'; "
            "img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; "
            "object-src 'none'; frame-ancestors 'none'")

def render_hardened(report):
    """Render self-contained UI with a hash-based CSP; no inline event attributes."""
    page=render_interactive(report)
    csp=csp_policy(page)
    return page.replace('<meta charset="utf-8">','<meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="'+html.escape(csp,quote=True)+'">',1)

