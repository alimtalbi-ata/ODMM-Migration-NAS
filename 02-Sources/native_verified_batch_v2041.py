"""V204.1 verified resumable batch using immutable per-file fingerprints."""
from pathlib import Path
from native_fidelity_manifest_v2041 import load_fidelity_manifest, verify_fingerprint
from native_verified_batch_v2040 import run_verified_batch
from native_tree_migration import NativeTreeMigration
from native_migration_errors import MigrationBlocked
SCHEMA="odmm-native-verified-batch-v2041"
def run_fidelity_batch(source,target,database,manifest_path,*,offset=0,limit=None):
    payload=load_fidelity_manifest(manifest_path)
    src=str(Path(source).resolve()); dst=str(Path(target).resolve())
    if src!=payload["source"] or dst!=payload["target"]: raise MigrationBlocked("CAMPAIGN_ROOT_MISMATCH")
    files=payload["files"]
    if type(offset) is not int or offset<0 or offset>len(files): raise ValueError("INVALID_OFFSET")
    if limit is not None and (type(limit) is not int or limit<0): raise ValueError("INVALID_LIMIT")
    stop=len(files) if limit is None else min(len(files),offset+limit); selected=files[offset:stop]
    # Validate source before any write, so known drift cannot cause a partial batch.
    for rel in selected:
        r=verify_fingerprint(Path(src)/rel,payload["fingerprints"][rel])
        if r["status"]!="MATCH": raise MigrationBlocked("SOURCE_FINGERPRINT_DRIFT:"+rel+":"+",".join(r["mismatches"]))
    # V204.0 wrapper requires its original V203.9 inventory manifest; construct no implicit fallback.
    # Accept only a matching original manifest explicitly supplied via sibling campaign_manifest.json.
    original=Path(manifest_path).with_name("campaign_manifest.json")
    if not original.is_file(): raise MigrationBlocked("V2039_MANIFEST_REQUIRED_AS_campaign_manifest.json")
    copied=run_verified_batch(source,target,database,original,offset=offset,limit=limit)
    checks=[]
    for rel in selected:
        src_check=verify_fingerprint(Path(src)/rel,payload["fingerprints"][rel])
        dst_check=verify_fingerprint(Path(dst)/rel,payload["fingerprints"][rel])
        checks.append({"path":rel,"source":src_check,"target":dst_check})
        if src_check["status"]!="MATCH": raise MigrationBlocked("SOURCE_CHANGED_DURING_BATCH:"+rel)
        if dst_check["status"]!="MATCH": raise MigrationBlocked("TARGET_FINGERPRINT_MISMATCH:"+rel)
    return {"schema":SCHEMA,"status":"BATCH_FINGERPRINT_VERIFIED_POSIX_SUBSET_ONLY","offset":offset,"next_offset":stop,"inventory_count":len(files),"processed_count":len(selected),"fingerprint_checks":checks,"copy_results":copied["copy_results"],"content_and_basic_posix_metadata_verified":True,"acl_fidelity_verified":False,"cutover_authorized":False}
