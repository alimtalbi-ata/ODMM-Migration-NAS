#!/usr/bin/env python3
"""Conservative evidence-driven triage. This tool NEVER deletes code."""
import argparse, ast, json, re
from pathlib import Path

def analyze(root):
    root=Path(root).resolve(); sources=root/'02-Sources'
    if not sources.is_dir(): raise ValueError('02-Sources directory missing')
    reach=json.loads((root/'07-Rapports/REACHABILITY-V228.19.json').read_text())
    runtime=json.loads((root/'07-Rapports/runtime-inventory-v22821.json').read_text())
    reachable=set(reach.get('reachable_modules',[]))
    references=set()
    for item in runtime.get('references',[]):
        value=item.get('value','')
        if item.get('kind')=='python-file':references.add(Path(value).stem)
        elif item.get('kind')=='python-module':references.add(value.split('.')[-1])
    files=sorted(p for p in sources.glob('*.py') if p.is_file())
    names={p.stem for p in files}; imported=set(); parse_errors=[]
    for p in files:
        try: tree=ast.parse(p.read_text(encoding='utf-8'))
        except (SyntaxError,UnicodeError) as e:parse_errors.append({'file':p.name,'error':str(e)});continue
        for n in ast.walk(tree):
            if isinstance(n,ast.Import): imported.update(a.name.split('.')[0] for a in n.names)
            elif isinstance(n,ast.ImportFrom) and n.module:imported.add(n.module.split('.')[0])
    protected=reachable|references
    rows=[]
    for p in files:
        name=p.stem; is_test=name.startswith('test_') or name.endswith('_test')
        family=re.sub(r'_v\d+(?:_\d+)*$','',name)
        evidence=[]
        if name in reachable:evidence.append('reachable_from_declared_python_root')
        if name in references:evidence.append('runtime_command_reference')
        if name in imported:evidence.append('imported_by_local_python')
        if is_test:evidence.append('test_module')
        if name in protected: decision='KEEP_PROTECTED'
        elif is_test:decision='REVIEW_TEST_COVERAGE'
        elif name in imported:decision='REVIEW_DEPENDENCY'
        else:decision='REVIEW_UNRESOLVED'
        rows.append({'module':name,'path':p.relative_to(root).as_posix(),'family':family,'decision':decision,'evidence':evidence,'deletion_authorized':False})
    families={}
    for r in rows:families.setdefault(r['family'],[]).append(r['module'])
    for r in rows:
        if len(families[r['family']])>1:r['evidence'].append('version_family_with_multiple_implementations')
    counts={k:sum(r['decision']==k for r in rows) for k in sorted({r['decision'] for r in rows})}
    return {'schema':'odmm.decision-matrix.v1','release':'228.22','method':'static evidence only; runtime behavior and dynamic imports not proven','deletion_authorized':False,'source_modules':len(rows),'counts':counts,'multiple_version_families':sum(len(v)>1 for v in families.values()),'parse_errors':parse_errors,'modules':rows,'limitations':['Import reachability is based on previously generated V228.19 report','Shell and build references are heuristic','Tests may use dynamic loading','Manual review and execution tests required before replacement or deletion']}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',default='.');ap.add_argument('--output');args=ap.parse_args()
    result=analyze(args.root);data=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:Path(args.output).write_text(data,encoding='utf-8')
    else:print(data)
if __name__=='__main__':main()
