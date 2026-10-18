#!/usr/bin/env python3
"""Audit read-only des points d’entrée, sans exécution de code métier."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'02-Sources'))
from odmm_entrypoint_contract import verify_contract

def main(argv=None):
 p=argparse.ArgumentParser(description='ODMM entrypoint contract check — no execution')
 p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
 p.add_argument('--output',type=Path)
 args=p.parse_args(argv)
 result=verify_contract(args.root)
 output=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
 if args.output:
  try:
   with args.output.open('x',encoding='utf-8') as f:f.write(output)
  except OSError:
   print('Cannot create output (existing or inaccessible)',file=sys.stderr);return 3
 else:print(output,end='')
 return 0 if result['pass'] else 2
if __name__=='__main__':sys.exit(main())
