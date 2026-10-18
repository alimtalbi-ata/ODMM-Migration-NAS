"""ODMM V201.3: offline campaign profiles and tamper-evident history. Author: Abdelhalim Talbi."""
import hashlib
import json
from pathlib import Path
from odmm_qualification_campaign_v2012 import verify_campaign

SCHEMA = "odmm.qualification.history.v2013"
PROTOCOLS = {"NFS3", "NFS4", "SMB2", "SMB3", "S3"}
VENDORS = {"NetApp", "Dell", "Pure", "IBM", "HPE", "Hitachi", "Generic"}
REQUIRED = ("content_sha256", "ownership", "attributes", "acl_evidence", "effective_access", "snapshot_consistency")

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def profile(source_vendor, target_vendor, source_protocol, target_protocol):
    if source_vendor not in VENDORS or target_vendor not in VENDORS:
        raise ValueError("UNKNOWN_VENDOR")
    if source_protocol not in PROTOCOLS or target_protocol not in PROTOCOLS:
        raise ValueError("UNKNOWN_PROTOCOL")
    result = {"schema": "odmm.qualification.profile.v2013", "author": "Abdelhalim Talbi",
              "source": {"vendor": source_vendor, "protocol": source_protocol},
              "target": {"vendor": target_vendor, "protocol": target_protocol},
              "required_evidence": list(REQUIRED), "vendor_qualified": False,
              "cross_protocol_semantics_verified": False, "cutover_authorized": False}
    result["profile_sha256"] = sha(result)
    return result

def verify_profile(value):
    return (isinstance(value, dict) and value.get("schema") == "odmm.qualification.profile.v2013"
            and value.get("profile_sha256") == sha({k:v for k,v in value.items() if k != "profile_sha256"})
            and value.get("required_evidence") == list(REQUIRED)
            and value.get("vendor_qualified") is False and value.get("cutover_authorized") is False
            and value.get("source",{}).get("vendor") in VENDORS
            and value.get("target",{}).get("vendor") in VENDORS
            and value.get("source",{}).get("protocol") in PROTOCOLS
            and value.get("target",{}).get("protocol") in PROTOCOLS)

def build_history(campaigns, qualification_profile):
    if not verify_profile(qualification_profile):
        raise ValueError("INVALID_PROFILE")
    if not isinstance(campaigns, list) or not campaigns:
        raise ValueError("EMPTY_HISTORY")
    entries=[]
    previous=None
    for index, campaign in enumerate(campaigns):
        if not verify_campaign(campaign):
            raise ValueError("INVALID_CAMPAIGN")
        item={"sequence":index, "campaign_sha256":campaign["report_sha256"],
              "profile_sha256":qualification_profile["profile_sha256"],
              "previous_entry_sha256":previous,
              "qualification":campaign["qualification"],
              "fidelity_sha256":campaign["fidelity"]["report_sha256"]}
        item["entry_sha256"]=sha(item)
        previous=item["entry_sha256"]
        entries.append(item)
    result={"schema":SCHEMA, "author":"Abdelhalim Talbi", "profile":qualification_profile,
            "entries":entries, "cutover_authorized":False, "vendor_qualified":False}
    result["history_sha256"]=sha(result)
    return result

def verify_history(value):
    if not isinstance(value,dict) or value.get("schema") != SCHEMA or not verify_profile(value.get("profile")):
        return False
    if value.get("cutover_authorized") is not False or value.get("vendor_qualified") is not False:
        return False
    entries=value.get("entries")
    if not isinstance(entries,list) or not entries:
        return False
    previous=None
    for i,entry in enumerate(entries):
        if (entry.get("sequence") != i or entry.get("previous_entry_sha256") != previous
            or entry.get("profile_sha256") != value["profile"]["profile_sha256"]
            or entry.get("entry_sha256") != sha({k:v for k,v in entry.items() if k!="entry_sha256"})):
            return False
        previous=entry["entry_sha256"]
    return value.get("history_sha256") == sha({k:v for k,v in value.items() if k!="history_sha256"})

def compare_history(history):
    if not verify_history(history):
        raise ValueError("INVALID_HISTORY")
    entries=history["entries"]
    transitions=[]
    for a,b in zip(entries,entries[1:]):
        transitions.append({"from":a["sequence"],"to":b["sequence"],
                            "fidelity_report_changed":a["fidelity_sha256"] != b["fidelity_sha256"],
                            "qualification_changed":a["qualification"] != b["qualification"],
                            "source_campaign_changed":a["campaign_sha256"] != b["campaign_sha256"]})
    return {"schema":"odmm.qualification.trends.v2013", "transitions":transitions,
            "cutover_authorized":False, "warning":"Digest changes indicate difference, not improvement or regression"}

def load_campaign(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 32*1024*1024:
        raise ValueError("INVALID_CAMPAIGN_FILE")
    value=json.loads(p.read_text(encoding="utf-8"))
    if not verify_campaign(value):
        raise ValueError("INVALID_CAMPAIGN")
    return value
