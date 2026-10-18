"""Offline SQLite audit ledger. Never performs migration or cutover."""
import argparse
import json
from pathlib import Path
from odmm_evidence_ledger_v22814 import record, verify

def main(argv=None):
    p=argparse.ArgumentParser(description="ODMM local evidence ledger (no cutover)")
    p.add_argument("--db",required=True,type=Path)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify",action="store_true")
    group.add_argument("--evidence",type=Path)
    p.add_argument("--job-id")
    args=p.parse_args(argv)
    try:
        if args.verify:
            if not args.db.is_file(): raise ValueError("missing database")
            outcome=verify(args.db)
        else:
            if not args.job_id: raise ValueError("job id required")
            with args.evidence.open("rb") as f: raw=f.read(1048577)
            if len(raw)>1048576: raise ValueError("oversize")
            outcome=record(args.db,args.job_id,json.loads(raw.decode("utf8")))
    except (OSError,ValueError,TypeError):
        p.exit(2,"ERROR: invalid input or inaccessible audit store\n")
    print(json.dumps(outcome,indent=2,ensure_ascii=False))
    if args.verify: return 0 if outcome["valid"] else 3
    return 3 if outcome["result"]["blocked_checks"] or outcome["result"]["anomalies"] else 0
if __name__=="__main__": raise SystemExit(main())
