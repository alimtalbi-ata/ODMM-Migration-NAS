"""Offline evidence assessment, never executes a migration."""
import argparse,json
from pathlib import Path
from odmm_market_readiness_v22812 import evaluate

def main(argv=None):
 p=argparse.ArgumentParser(description="ODMM offline migration evidence review (no cutover)")
 p.add_argument("--evidence",required=True,type=Path)
 a=p.parse_args(argv)
 try:
  raw=a.evidence.read_text(encoding="utf-8")
  if len(raw)>1024*1024: raise ValueError("Evidence exceeds 1 MiB")
  result=evaluate(json.loads(raw))
 except (OSError,ValueError,UnicodeError) as exc:
  p.exit(2,"ERROR: invalid or inaccessible evidence document\n")
 print(json.dumps(result,ensure_ascii=False,indent=2))
 return 0 if not result["blocked_checks"] else 3
if __name__=="__main__": raise SystemExit(main())
