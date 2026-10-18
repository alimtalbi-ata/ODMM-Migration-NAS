"""Conservative static reachability of ODMM local Python modules. No execution."""
import ast
from collections import deque
from pathlib import Path
import re

def analyze(root, entrypoints):
    root=Path(root).resolve(); source=root/'02-Sources'
    modules={p.stem:p for p in source.glob('*.py') if p.is_file()}
    graph={}; dynamic=[]; parse_errors=[]
    for name,path in sorted(modules.items()):
        try: tree=ast.parse(path.read_text(encoding='utf-8-sig'),filename=str(path))
        except (SyntaxError,UnicodeError) as exc:
            parse_errors.append({'module':name,'error':type(exc).__name__});graph[name]=set();continue
        deps=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                deps.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module:
                deps.add(node.module.split('.')[0])
            elif isinstance(node,ast.Call):
                f=node.func
                if (isinstance(f,ast.Name) and f.id in ('__import__','import_module','exec','eval')) or (isinstance(f,ast.Attribute) and f.attr in ('import_module','exec_module')):
                    dynamic.append({'module':name,'line':node.lineno,'function':getattr(f,'id',getattr(f,'attr',''))})
        graph[name]=deps & modules.keys()
    seeds=set(); unresolved=[]; scripts=[]
    for rel in entrypoints:
        p=(root/rel).resolve()
        if not p.is_relative_to(root) or not p.is_file():
            unresolved.append(rel);continue
        if p.suffix=='.py':
            if p.stem in modules:seeds.add(p.stem)
            else:
                # CLI wrappers outside SOURCE: parse their direct imports
                try:
                    tree=ast.parse(p.read_text(encoding='utf-8-sig'))
                    for n in ast.walk(tree):
                        if isinstance(n,ast.Import):seeds.update(a.name.split('.')[0] for a in n.names if a.name.split('.')[0] in modules)
                        if isinstance(n,ast.ImportFrom) and n.module and n.module.split('.')[0] in modules:seeds.add(n.module.split('.')[0])
                except (SyntaxError,UnicodeError):unresolved.append(rel)
        else:
            scripts.append(rel)
            # scripts can invoke arbitrary programs: never infer reachability from text
    reachable=set(); queue=deque(sorted(seeds))
    while queue:
        name=queue.popleft()
        if name in reachable:continue
        reachable.add(name)
        queue.extend(sorted(graph.get(name,set())-reachable))
    return {'schema':'odmm.static-reachability.v1','release':'228.19','module_count':len(modules),
      'python_roots':sorted(seeds),'non_python_entrypoints_not_traversed':scripts,
      'missing_entrypoints':unresolved,'reachable_count':len(reachable),
      'reachable_modules':sorted(reachable),'not_statically_reached':sorted(modules.keys()-reachable),
      'dynamic_import_indicators':dynamic,'parse_errors':parse_errors,
      'interpretation':'Not statically reached does NOT mean dead code; no modules removed.'}
