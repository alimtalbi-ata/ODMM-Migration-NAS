"""Read-only evidence audit CLI, fail closed on malformed input."""
import argparse, json
from pathlib import Path
from odmm_evidence_audit_v22813 import audit

def main(argv=None):
    p=argparse.ArgumentParser(description="ODMM evidence audit, never authorizes cutover")
    p.add_argument("--evidence",required=True,type=Path)
    p.add_argument("--job-id",help="Require evidence bound to this job")
    args=p.parse_args(argv)
    try:
        with args.evidence.open("rb") as f:
            raw=f.read(1024*1024+1)
        if len(raw)>1024*1024: raise ValueError("too large")
        payload=json.loads(raw.decode("utf-8"))
        result=audit(payload,args.job_id)
    except (OSError, ValueError, UnicodeError, TypeError):
        p.exit(2,"ERROR: evidence unavailable or invalid\n")
    print(json.dumps(result,indent=2,ensure_ascii=False))
    return 3 if result["blocked_checks"] or result["anomalies"] else 0
if __name__=="__main__": raise SystemExit(main())
