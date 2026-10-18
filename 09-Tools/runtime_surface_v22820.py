#!/usr/bin/env python3
"""Read-only launcher surface inventory; conservative evidence, never deletion advice."""
import argparse, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'02-Sources'))
from odmm_entrypoint_contract import EDITION_CONTRACT
from odmm_static_reachability import analyze
PATTERNS={
 'python':re.compile(r'(?<![\w/.-])(?:python(?:3(?:\.\d+)?)?|py)(?:\s+-[\w]+)*\s+["\']?([\w./-]+\.py)',re.I),
 'shell':re.compile(r'(?:^|[\s"\'])([\w./-]+\.sh)(?=$|[\s"\'])',re.I),
 'windows':re.compile(r'(?:^|[\s"\'])([\w./-]+\.(?:cmd|bat|ps1))(?=$|[\s"\'])',re.I),
}
def scan(root):
 root=Path(root).resolve()
 contract=[v['launcher'] for v in EDITION_CONTRACT.values()]
 reachable=analyze(root,contract)
 entries=[]; missing=[]; unsafe=[]
 for edition, item in EDITION_CONTRACT.items():
  rel=item['launcher']; p=(root/rel).resolve()
  if not p.is_relative_to(root):unsafe.append(rel);continue
  if not p.is_file():missing.append(rel);continue
  try: content=p.read_text(encoding='utf-8-sig')
  except UnicodeError:content=''
  refs=[]
  for kind,pat in PATTERNS.items():
   for match in pat.finditer(content):
    value=match.group(1)
    if value.startswith(('/', '\\')) or '..' in Path(value).parts:
     refs.append({'kind':kind,'literal':value,'status':'external_or_ambiguous'});continue
    candidates=[(p.parent/value).resolve(),(root/value).resolve(),(root/'02-Sources'/value).resolve()]
    found=[q.relative_to(root).as_posix() for q in candidates if q.is_relative_to(root) and q.is_file()]
    refs.append({'kind':kind,'literal':value,'status':'found' if found else 'unresolved','candidates':sorted(set(found))})
  entries.append({'edition':edition,'role':item['launcher_role'],'launcher':rel,'references':refs})
 return {'schema':'odmm.runtime-surface.v1','release':'228.20','entries':entries,
 'missing_launchers':missing,'unsafe_paths':unsafe,
 'static_python_reachable_count':reachable['reachable_count'],
 'static_python_not_reached_count':len(reachable['not_statically_reached']),
 'dynamic_import_indicators_count':len(reachable['dynamic_import_indicators']),
 'disposition':{'retain':'All current modules pending execution tests',
 'replace':'Version-suffixed duplicate families require owner and behavior parity review',
 'remove':'None approved by this read-only analysis'},
 'limitations':['Only explicit launcher scripts in the edition contract are scanned',
 'Regex references may be comments, examples or build-time only',
 'Indirect process launch, runtime plugins and external dependencies are not resolved',
 'No code is executed or removed']}
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--output',type=Path);args=p.parse_args()
 data=scan(args.root);body=json.dumps(data,indent=2,ensure_ascii=False)+'\n'
 if args.output:
  with args.output.open('x',encoding='utf-8') as f:f.write(body)
 else:print(body,end='')
 return 2 if data['missing_launchers'] or data['unsafe_paths'] else 0
if __name__=='__main__':raise SystemExit(main())
