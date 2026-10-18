#!/usr/bin/env python3
"""Non-destructive ODMM static entrypoint dependency map."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'02-Sources'))
from odmm_entrypoint_contract import EDITION_CONTRACT
from odmm_static_reachability import analyze

def main(argv=None):
 p=argparse.ArgumentParser()
 p.add_argument('--root',type=Path,default=ROOT)
 p.add_argument('--output',type=Path)
 args=p.parse_args(argv)
 report=analyze(args.root,[x['launcher'] for x in EDITION_CONTRACT.values()])
 payload=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
 if args.output:
  try:
   with args.output.open('x',encoding='utf-8') as f:f.write(payload)
  except OSError:
   print('Cannot create report (exists or inaccessible)',file=sys.stderr);return 3
 else:print(payload,end='')
 return 2 if report['missing_entrypoints'] or report['parse_errors'] else 0
if __name__=='__main__':sys.exit(main())
