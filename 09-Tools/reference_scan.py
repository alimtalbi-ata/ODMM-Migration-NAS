#!/usr/bin/env python3
"""Conservative cross-language entrypoint and reference discovery. Never deletes sources."""
import argparse,ast,collections,hashlib,json,pathlib,re
EXT={'.py','.sh','.bash','.cmd','.bat','.ps1','.iss','.toml','.ini','.cfg','.yaml','.yml','.json','.md','.txt','.service','.desktop'}
SKIP={'__pycache__','.pytest_cache','.git','node_modules','.venv','venv'}
PATTERNS=[('python_import',r'(?m)^\s*(?:from|import)\s+{stem}(?:\b|\.)'),('script_or_config',r'(?<![A-Za-z0-9_]){filename}(?![A-Za-z0-9_])'),('dynamic_module',r'(?<![A-Za-z0-9_]){stem}(?![A-Za-z0-9_])')]
def scan(root):
 root=pathlib.Path(root).resolve(); py=sorted(p for p in root.rglob('*.py') if not any(x in SKIP for x in p.parts)); candidates=sorted(p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in EXT and not any(x in SKIP for x in p.parts)); contents={}
 for p in candidates:
  try:
   if p.stat().st_size<=2_000_000: contents[p]=p.read_text(encoding='utf-8-sig',errors='replace')
  except OSError: pass
 out=[]
 for p in py:
  rel=p.relative_to(root).as_posix(); stem=p.stem; name=p.name; hits=[]
  for other,data in contents.items():
   if other==p or (other.suffix=='.py' and other.parent!=p.parent):continue
   if stem not in data and name not in data:continue
   for typ,pattern in PATTERNS:
    if re.search(pattern.format(stem=re.escape(stem),filename=re.escape(name)),data):
     hits.append({'source':other.relative_to(root).as_posix(),'kind':typ});break
  try:
   tree=ast.parse(contents.get(p,p.read_text(encoding='utf-8-sig',errors='replace')))
   main=any(isinstance(n,ast.If) and '__main__' in ast.unparse(n.test) for n in tree.body)
  except (SyntaxError,ValueError):main=False
  out.append({'module':rel,'references':hits,'reference_count':len(hits),'main_guard':main,'classification':('referenced' if hits else 'entrypoint_candidate' if main else 'manual_review'),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 counts=dict(collections.Counter(x['classification'] for x in out));return {'schema':'odmm.reference_scan.v1','source_root':str(root),'statistics':{'modules':len(out),'scanned_text_files':len(contents),'classifications':counts},'modules':out,'caveats':['Textual references are evidence of mention, not proof of execution.','Dynamic imports, subprocess calls, external deployment and generated entrypoints may be missed.','No module is safe to delete based on this report alone.']}
def main():
 a=argparse.ArgumentParser();a.add_argument('--root',required=True);a.add_argument('--output',required=True);args=a.parse_args();report=scan(args.root);p=pathlib.Path(args.output);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps(report['statistics'],ensure_ascii=False))
if __name__=='__main__':main()
