#!/usr/bin/env python3
"""Conservative runtime surface inventory; NEVER authorizes deletion."""
import argparse, json, re
from pathlib import Path
EXT={'.sh','.bash','.cmd','.bat','.ps1','.service','.toml','.yaml','.yml','.json','.ini','.cfg','.py','.spec'}
PATTERNS=[('python-module',r'(?<![\w.])(?:python(?:3(?:\.\d+)?)?\s+(?:-[^\s]+\s+)*-m\s+)([\w.]+)'),('python-file',r'(?<![\w.])(?:python(?:3(?:\.\d+)?)?\s+(?:-[^\s]+\s+)*)([\w./-]+\.py)'),('shell-source',r'(?<![\w])(?:source|\.)\s+([\w./-]+\.(?:sh|bash))'),('systemd-exec',r'(?m)^\s*ExecStart\s*=\s*(.+)$'),('docker-entrypoint',r'(?i)\b(?:entrypoint|command)\s*[:=]\s*(.+)$')]
def inventory(root):
    root=Path(root).resolve(); rows=[]; errors=[]
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in EXT or any(x in path.parts for x in ('__pycache__','.git','.venv','node_modules')): continue
        rel=path.relative_to(root).as_posix()
        try: data=path.read_text(encoding='utf-8',errors='replace')
        except OSError as e: errors.append({'file':rel,'error':str(e)});continue
        for kind,pattern in PATTERNS:
            for m in re.finditer(pattern,data):
                value=m.group(1).strip()[:300]
                if not value:continue
                target=(path.parent/value).resolve() if kind in ('python-file','shell-source') else None
                rows.append({'source':rel,'line':data.count('\n',0,m.start())+1,'kind':kind,'value':value,'local_target_exists':target.is_file() if target and target.is_relative_to(root) else None})
    return {'schema':'odmm.runtime_inventory.v1','scope':'static heuristic only; dynamic imports, runtime services and external calls not proven','references':rows,'read_errors':errors,'summary':{'references':len(rows),'files_with_references':len(set(r['source'] for r in rows)),'missing_local_targets':sum(r['local_target_exists'] is False for r in rows)}}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',default='.');ap.add_argument('--output');a=ap.parse_args(); result=inventory(a.root); data=json.dumps(result,indent=2,ensure_ascii=False)
    if a.output:Path(a.output).write_text(data+'\n',encoding='utf-8')
    else:print(data)
if __name__=='__main__':main()
