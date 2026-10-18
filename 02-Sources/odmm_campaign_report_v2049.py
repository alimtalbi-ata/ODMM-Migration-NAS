"""Read-only export of existing fidelity assessments. Auteur : Abdelhalim Talbi."""
import json
from pathlib import Path
from native_fidelity_gate_v2043 import history

SCHEMA='odmm.campaign_report.v2049'

def build_report(db_path, campaign_id):
    if not isinstance(campaign_id,str) or not campaign_id.strip():
        raise ValueError('INVALID_CAMPAIGN')
    records=history(db_path,campaign_id)
    statuses=[r['status'] for r in records]
    return {'schema':SCHEMA,'author':'Abdelhalim Talbi','campaign_id':campaign_id,
            'assessments':len(records),'latest_status':statuses[-1] if statuses else 'NO_EVIDENCE',
            'status_history':statuses,'total_mismatches':sum(r['mismatches'] for r in records),
            'total_unverified':sum(r['unverified'] for r in records),
            'validation_authorized':False,'cutover_authorized':False,
            'notice':'Local registry evidence only; no live NAS ACL/identity certification'}

def export_report(db_path,campaign_id,output_path):
    """Explicit operator-selected output; never writes source/target NAS."""
    out=Path(output_path)
    if out.is_symlink() or out.exists(): raise FileExistsError('OUTPUT_EXISTS_OR_UNSAFE')
    report=build_report(db_path,campaign_id)
    with out.open('x',encoding='utf-8') as f:
        json.dump(report,f,indent=2,ensure_ascii=False)
        f.write('\n')
    return report
