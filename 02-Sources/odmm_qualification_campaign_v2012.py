"""ODMM V201.2 offline NAS pair qualification campaign. Author: Abdelhalim Talbi.
No writes to NAS roots, no automatic cutover or vendor certification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from odmm_nas_evidence_collector_v2006 import collect
from odmm_migration_fidelity_report_v2011 import build_report, verify_report_digest

class CampaignError(ValueError): pass

def digest(data):
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def qualify(source, target, *, max_entries=100000, max_bytes=1<<40, acl_report=None, access_report=None):
    src=Path(source); dst=Path(target)
    if src.is_symlink() or dst.is_symlink() or not src.is_dir() or not dst.is_dir():
        raise CampaignError('INVALID_MOUNT_ROOT')
    a=src.resolve(strict=True);b=dst.resolve(strict=True)
    if a==b or a in b.parents or b in a.parents: raise CampaignError('OVERLAPPING_ROOTS')
    source_inv=collect(a,max_entries=max_entries,max_bytes=max_bytes)
    target_inv=collect(b,max_entries=max_entries,max_bytes=max_bytes)
    fidelity=build_report(source_inv,target_inv,acl_report=acl_report,access_report=access_report)
    if not verify_report_digest(fidelity): raise CampaignError('INVALID_FIDELITY_DIGEST')
    report={'schema':'odmm.qualification.campaign.v2012','author':'Abdelhalim Talbi',
            'source_root':str(a),'target_root':str(b),'source_inventory_sha256':digest(source_inv),
            'target_inventory_sha256':digest(target_inv),'fidelity':fidelity,
            'qualification':'BLOCKED_PENDING_INDEPENDENT_NAS_TESTS',
            'cutover_authorized':False,'native_engine_default':True,'writes_to_nas':False,
            'limitations':['ACL semantic equivalence unverified','AD/LDAP access not independently attested',
                           'No point-in-time snapshot consistency proof','No vendor interoperability certification']}
    report['report_sha256']=digest(report)
    return report

def verify_campaign(report):
    if not isinstance(report,dict) or report.get('schema')!='odmm.qualification.campaign.v2012': return False
    if not verify_report_digest(report.get('fidelity')): return False
    return report.get('report_sha256')==digest({k:v for k,v in report.items() if k!='report_sha256'})

def save_report(report, output, source, target):
    if not verify_campaign(report): raise CampaignError('INVALID_CAMPAIGN_DIGEST')
    path=Path(output).absolute()
    for root in (Path(source).resolve(),Path(target).resolve()):
        if path==root or root in path.parents: raise CampaignError('OUTPUT_INSIDE_NAS_ROOT')
    if path.is_symlink(): raise CampaignError('OUTPUT_SYMLINK')
    if not path.parent.is_dir(): raise CampaignError('OUTPUT_PARENT_MISSING')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        json.dump(report,stream,ensure_ascii=False,sort_keys=True,indent=2)
        stream.write('\n')
    return path

def main(argv=None):
    parser=argparse.ArgumentParser(description='Read-only ODMM NAS qualification campaign')
    parser.add_argument('--source',required=True);parser.add_argument('--target',required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--max-entries',type=int,default=100000)
    parser.add_argument('--max-bytes',type=int,default=1<<40)
    args=parser.parse_args(argv)
    result=qualify(args.source,args.target,max_entries=args.max_entries,max_bytes=args.max_bytes)
    save_report(result,args.output,args.source,args.target)
    print(json.dumps({'status':result['qualification'],'report_sha256':result['report_sha256'],'output':args.output}))
    return 2 # deliberately never return success for unqualified cutover
if __name__=='__main__': raise SystemExit(main())
