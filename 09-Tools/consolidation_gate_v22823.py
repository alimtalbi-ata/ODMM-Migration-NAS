#!/usr/bin/env python3
"""Evidence-based, fail-closed ODMM consolidation planner. Never deletes files."""
import argparse, ast, json, re
from pathlib import Path

VERSION_RE = re.compile(r'^(?P<family>.+?)_v\d+(?:_\d+)*$')

def inspect(root):
    root=Path(root).resolve()
    src=root/'02-Sources'
    if not src.is_dir():raise ValueError('Missing 02-Sources')
    paths=sorted(src.rglob('*.py'))
    stems={p.stem for p in paths}
    imports={p.stem:set() for p in paths}
    errors=[]
    for p in paths:
        try: tree=ast.parse(p.read_text(encoding='utf-8-sig'))
        except (SyntaxError,UnicodeError) as e:
            errors.append({'file':str(p.relative_to(root)),'error':str(e)});continue
        for n in ast.walk(tree):
            if isinstance(n,ast.Import):
                imports[p.stem].update(a.name.split('.')[0] for a in n.names)
            elif isinstance(n,ast.ImportFrom) and n.module:
                imports[p.stem].add(n.module.split('.')[0])
    referenced={x for names in imports.values() for x in names if x in stems}
    family={}
    for p in paths:
        m=VERSION_RE.match(p.stem)
        family.setdefault(m.group('family') if m else p.stem,[]).append(p)
    candidates=[]
    for fam, members in sorted(family.items()):
        if len(members)<2:continue
        candidates.append({'family':fam,'members':[p.relative_to(root).as_posix() for p in members],
          'referenced_members':[p.stem for p in members if p.stem in referenced],
          'decision':'REVIEW_ONLY','delete_authorized':False})
    unresolved=[p.relative_to(root).as_posix() for p in paths if p.stem not in referenced and not p.stem.startswith('test_')]
    return {'schema':'odmm.consolidation-gate.v1','version':'228.23','total_modules':len(paths),
      'versioned_families':len(candidates),'families':candidates,
      'unreferenced_by_static_imports':unresolved,'parse_errors':errors,
      'delete_authorized':False,'limitations':['Static import graph is not a runtime trace',
      'File names may collide across directories','Dynamic imports, shell entrypoints and plugin discovery need runtime tests',
      'Unreferenced does not mean unused']}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',default='.');parser.add_argument('--output')
    args=parser.parse_args();result=inspect(args.root)
    output=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:Path(args.output).write_text(output,encoding='utf-8')
    else:print(output)
if __name__=='__main__':main()
