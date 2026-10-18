"""Comparaison conservative des exports API hors ligne. Auteur: Abdelhalim Talbi."""
import hashlib
import json
from odmm_vendor_offline_adapter_v2053 import normalize_export

def compare_exports(source_vendor, source, target_vendor, target):
    a=normalize_export(source_vendor,source)
    b=normalize_export(target_vendor,target)
    evidence={"source":a,"target":b}
    canonical=json.dumps(evidence,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    return {"schema_version":"205.4","source":a,"target":b,
            "evidence_sha256":hashlib.sha256(canonical.encode()).hexdigest(),
            "compatibility":"NOT_ASSESSED","acl_fidelity":"UNVERIFIED",
            "identity_mapping":"UNVERIFIED","effective_access":"UNVERIFIED",
            "cutover_authorized":False,"status":"REQUIRES_MANUAL_QUALIFICATION",
            "warnings":["Comparaison des inventaires déclaratifs uniquement",
                        "Absence de preuve ACL et d'accès effectif",
                        "Le SHA256 atteste l'intégrité du résumé, pas son authenticité"]}
