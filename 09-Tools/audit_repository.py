#!/usr/bin/env python3
"""Static inventory of ODMM. Conservative: reports candidates, never deletes code."""
import argparse, ast, collections, hashlib, json, pathlib, re, sys

def audit(root):
    root=pathlib.Path(root).resolve()
    files=sorted(root.rglob('*.py'))
    modules={p.stem:p for p in files if p.parent==root}
    records=[]; edges=[]; parse_errors=[]; families=collections.defaultdict(list)
    for p in files:
        rel=p.relative_to(root).as_posix()
        raw=p.read_bytes()
        try: tree=ast.parse(raw.decode('utf-8-sig'), filename=rel)
        except (SyntaxError,UnicodeError) as e:
            parse_errors.append({'file':rel,'error':type(e).__name__,'line':getattr(e,'lineno',None)}); continue
        imports=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import): imports.update(n.name.split('.')[0] for n in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module: imports.add(node.module.split('.')[0])
        local=sorted(i for i in imports if i in modules and modules[i]!=p)
        edges.extend({'from':rel,'to':modules[i].relative_to(root).as_posix()} for i in local)
        version_match=re.match(r'^(.*?)(?:_v\d+(?:_\d+)*)$',p.stem)
        if version_match: families[version_match.group(1)].append(rel)
        records.append({'file':rel,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(), 'imports_local':local,'has_main_guard':any(isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and isinstance(n.test.left,ast.Name) and n.test.left.id=='__name__' for n in tree.body),'tests':p.name.startswith('test_')})
    incoming=collections.Counter(e['to'] for e in edges)
    zero_incoming=[r['file'] for r in records if incoming[r['file']]==0 and not r['tests']]
    version_families=[{'family':k,'count':len(v),'files':v} for k,v in families.items() if len(v)>1]
    version_families.sort(key=lambda x:(-x['count'],x['family']))
    hash_groups=collections.defaultdict(list)
    for r in records: hash_groups[r['sha256']].append(r['file'])
    exact_duplicates=[v for v in hash_groups.values() if len(v)>1]
    return {'schema':'odmm.audit.v1','root':str(root),'statistics':{'python_files':len(files),'parsed':len(records),'parse_errors':len(parse_errors),'test_files':sum(r['tests'] for r in records),'versioned_files':sum(bool(re.search(r'_v\d',r['file'])) for r in records),'local_import_edges':len(edges),'multiple_version_families':len(version_families),'exact_duplicate_groups':len(exact_duplicates),'zero_incoming_non_tests':len(zero_incoming)},'parse_errors':parse_errors,'version_families':version_families,'exact_duplicate_groups':exact_duplicates,'zero_incoming_non_tests':zero_incoming,'edges':edges,'files':records,'limitations':['Static imports only; dynamic imports, shell references and runtime configuration not resolved.','Zero incoming is NOT proof of dead code.','No files are deleted by this audit.']}

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    result=audit(a.source);out=pathlib.Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps(result['statistics'],ensure_ascii=False));return 0 if not result['parse_errors'] else 2
if __name__=='__main__':sys.exit(main())
