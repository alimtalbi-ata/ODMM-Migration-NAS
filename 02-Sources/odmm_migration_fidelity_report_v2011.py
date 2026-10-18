"""ODMM V201.1: conservative aggregate of independent NAS migration evidence.
Author: Abdelhalim Talbi. Report is not a cutover authorization.
"""
import hashlib
import json
from odmm_nas_evidence_collector_v2006 import compare as compare_inventory

class FidelityReportError(ValueError): pass

def build_report(source_inventory, target_inventory, *, acl_report=None, access_report=None,
                 required_domains=("content", "metadata", "acl", "effective_access")):
    """Fail-closed: all input reports must have recognized schema and non-empty evidence.

    Accepts independent evidence reports; does not attest their provenance, trust,
    storage snapshot consistency or cross-protocol semantic equivalence.
    """
    allowed={"content", "metadata", "acl", "effective_access"}
    if not isinstance(required_domains,(list,tuple)) or not required_domains or set(required_domains)!=allowed:
        raise FidelityReportError("REQUIRED_DOMAINS_MUST_INCLUDE_ALL")
    if not isinstance(source_inventory,dict) or not isinstance(target_inventory,dict):
        raise FidelityReportError("INVALID_INVENTORY")
    for inv in (source_inventory,target_inventory):
        if inv.get("schema")!="odmm.nas.readonly.inventory.v2006" or not isinstance(inv.get("entries"),dict):
            raise FidelityReportError("INVALID_INVENTORY")
        if inv.get("entry_count")!=len(inv["entries"]): raise FidelityReportError("INCONSISTENT_INVENTORY_COUNT")
    pair=compare_inventory(source_inventory,target_inventory)
    domains={}
    data_issues=[d for d in pair["differences"] if d["issue"] in ("TARGET_MISSING","SOURCE_MISSING","MISMATCH_KIND","MISMATCH_SIZE","MISMATCH_SHA256","UNVERIFIED_SHA256")]
    metadata_issues=[d for d in pair["differences"] if d not in data_issues]
    for name,issues in (("content",data_issues),("metadata",metadata_issues)):
        domains[name]={"status":"BLOCKED" if issues or not source_inventory["entries"] else "OBSERVED_MATCH_NOT_ATTESTED",
                       "issues":issues if issues else ([{"issue":"EMPTY_INVENTORY"}] if not source_inventory["entries"] else [])}
    if acl_report is None:
        domains["acl"]={"status":"UNVERIFIED","issues":[{"issue":"ACL_EVIDENCE_MISSING"}]}
    elif not isinstance(acl_report,dict) or acl_report.get("schema") not in ("odmm.acl.effective.validation.v2005", "odmm.acl.canonical.v2009"):
        domains["acl"]={"status":"BLOCKED","issues":[{"issue":"ACL_REPORT_SCHEMA_UNRECOGNIZED"}]}
    else:
        # Presence of a syntactically recognized report is not equivalent to a verified ACL.
        domains["acl"]={"status":"UNVERIFIED","issues":[{"issue":"ACL_SEMANTIC_EQUIVALENCE_NOT_ATTESTED"}]}
    if access_report is None:
        domains["effective_access"]={"status":"UNVERIFIED","issues":[{"issue":"ACCESS_EVIDENCE_MISSING"}]}
    elif not isinstance(access_report,dict) or access_report.get("schema")!="odmm.access.evidence.v2010":
        domains["effective_access"]={"status":"BLOCKED","issues":[{"issue":"ACCESS_REPORT_SCHEMA_UNRECOGNIZED"}]}
    else:
        domains["effective_access"]={"status":"UNVERIFIED","issues":[{"issue":"ACCESS_EVIDENCE_NOT_INDEPENDENTLY_ATTESTED"}]}
    payload={"schema":"odmm.migration.fidelity.report.v2011","author":"Abdelhalim Talbi",
             "source_entries":source_inventory["entry_count"],"target_entries":target_inventory["entry_count"],
             "domains":domains,"status":"BLOCKED_PENDING_INDEPENDENT_QUALIFICATION",
             "cutover_authorized":False,"acl_fidelity_verified":False,"effective_access_verified":False,
             "native_engine_default":True,"writes_performed":False,
             "limitations":["No live NAS certification","No snapshot consistency attestation","No remote identity attestation"]}
    payload["report_sha256"]=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    return payload

def verify_report_digest(report):
    if not isinstance(report,dict) or report.get("schema")!="odmm.migration.fidelity.report.v2011": return False
    raw={k:v for k,v in report.items() if k!="report_sha256"}
    return hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()==report.get("report_sha256")
