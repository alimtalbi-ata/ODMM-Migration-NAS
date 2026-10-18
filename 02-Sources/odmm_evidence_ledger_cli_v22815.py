"""Offline audit verification and anchor export; no migration actions."""
import argparse
import json
from pathlib import Path
from odmm_evidence_ledger_v22815 import inspect,anchor,check_anchor

def main(argv=None):
    p=argparse.ArgumentParser(description="ODMM audit verification, read-only")
    p.add_argument("--db",required=True,type=Path)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--verify",action="store_true")
    g.add_argument("--anchor-out",type=Path)
    g.add_argument("--check-anchor",type=Path)
    a=p.parse_args(argv)
    try:
        if a.anchor_out:
            result=anchor(a.db)
            with a.anchor_out.open("x",encoding="utf8") as f:
                json.dump(result,f,indent=2); f.write("\n")
        elif a.check_anchor:
            with a.check_anchor.open(encoding="utf8") as f: reference=json.load(f)
            result=check_anchor(a.db,reference)
        else: result=inspect(a.db)
    except (OSError,ValueError,TypeError,KeyError,Exception) as exc:
        p.exit(2,"ERROR: audit store or anchor unavailable/invalid\n")
    print(json.dumps(result,indent=2))
    return 0 if result["valid"] else 3
if __name__=="__main__": raise SystemExit(main())
