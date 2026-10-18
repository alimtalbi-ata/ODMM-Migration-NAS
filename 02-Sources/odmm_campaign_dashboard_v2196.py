"""Read-only, fail-closed directory audit dashboard exporter. Author: Abdelhalim Talbi."""
import html
import json
import sqlite3
from pathlib import Path
from odmm_access_anchor_v2185 import verify_anchored
from odmm_access_audit_v2184 import AuditError, digest, _verify_rows


def build_dashboard(audit_path, anchor_path, *, identity=None, only_mismatches=False):
    status = verify_anchored(audit_path, anchor_path)
    db = sqlite3.connect(f'file:{Path(audit_path).resolve()}?mode=ro', uri=True)
    try:
        db.execute('BEGIN')
        rows = db.execute('SELECT seq,previous,payload,hash FROM audit ORDER BY seq').fetchall()
        if _verify_rows(rows) != status['head'] or len(rows) != status['entries']:
            raise AuditError('AUDIT_CHANGED_DURING_EXPORT')
        items=[]
        for seq, _, raw, head in rows:
            payload=json.loads(raw)
            campaign=payload.get('campaign',{})
            report=campaign.get('report',{})
            if report.get('schema')!='odmm.directory-audit.v2195':
                continue
            if digest(report)!=campaign.get('sha256'):
                raise AuditError('INVALID_DIRECTORY_EVIDENCE')
            for case in report.get('cases',[]):
                if not isinstance(case,dict) or not all(k in case for k in ('case_id','identity_ref','groups_equal','local_access_equal')):
                    raise AuditError('INVALID_CASE')
                if type(case['groups_equal']) is not bool or type(case['local_access_equal']) is not bool:
                    raise AuditError('INVALID_CASE_FLAGS')
                if identity is not None and case['identity_ref']!=identity: continue
                mismatch=not(case['groups_equal'] and case['local_access_equal'])
                if only_mismatches and not mismatch: continue
                items.append({'seq':seq,'head':head,'case_id':case['case_id'], 'identity_ref':case['identity_ref'],
                              'groups_equal':case['groups_equal'],'local_access_equal':case['local_access_equal'],
                              'mismatch':mismatch})
        db.execute('COMMIT')
        return {'schema':'odmm.campaign-dashboard.v2196','audit_head':status['head'], 'entries':status['entries'],
                'anchored':True,'identity_filter':identity,'only_mismatches':bool(only_mismatches),
                'cases':items,'case_count':len(items),'mismatch_count':sum(x['mismatch'] for x in items),
                'nas_qualified':False,'cutover_authorized':False,
                'limitations':['LOCAL_ANCHOR_NOT_WORM','NO_PHYSICAL_NAS_QUALIFICATION','NO_AUTHENTICATED_NAS_ACCESS_TEST']}
    finally:
        db.close()


def render_html(report):
    if report.get('schema')!='odmm.campaign-dashboard.v2196' or report.get('cutover_authorized') is not False:
        raise AuditError('INVALID_DASHBOARD')
    esc=lambda v:html.escape(str(v),quote=True)
    trs=''.join('<tr><td>'+esc(x['seq'])+'</td><td>'+esc(x['case_id'])+'</td><td>'+esc(x['identity_ref'])+'</td><td>'+('Écart' if x['mismatch'] else 'Identique')+'</td><td>'+('Oui' if x['groups_equal'] else 'Non')+'</td><td>'+('Oui' if x['local_access_equal'] else 'Non')+'</td></tr>' for x in report['cases'])
    return ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM — Audit campagnes</title>'
            '<style>body{font:16px system-ui;margin:2rem;background:#f4f7fb;color:#14243b}main{max-width:1150px;margin:auto}table{border-collapse:collapse;width:100%;background:white}th,td{padding:12px;border-bottom:1px solid #d9e1ee;text-align:left}th{background:#dce9fa}.warn{color:#9a3412;font-weight:bold}.stats{font-size:1.3rem}</style>'
            '<main><h1>ODMM — Campagnes multi-identités</h1><p class="warn">Prévalidation locale uniquement — cutover interdit — NAS non qualifié</p>'
            '<p class="stats">Cas : '+esc(report['case_count'])+' | Écarts : '+esc(report['mismatch_count'])+'</p>'
            '<p>Ancrage local vérifié · Tête : <code>'+esc(report['audit_head'])+'</code></p>'
            '<table><thead><tr><th>Audit</th><th>Cas</th><th>Identité</th><th>Résultat</th><th>Groupes</th><th>Accès local</th></tr></thead><tbody>'+trs+'</tbody></table>'
            '<p>Rapport en lecture seule · Auteur : Abdelhalim Talbi</p></main></html>')
