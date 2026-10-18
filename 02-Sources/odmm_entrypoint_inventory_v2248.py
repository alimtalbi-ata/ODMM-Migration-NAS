"""Read-only entrypoint inventory; author Abdelhalim Talbi."""
from __future__ import annotations
import argparse, ast, json
from pathlib import Path

CANDIDATES = ('odmm_operations_app.py','odmm_operations_cli.py','odmm_production_entrypoint.py','odmm_scoped_app.py','odmm_scoped_cli.py','odmm_oidc_http_entrypoint.py','odmm_audit_cli.py')

def inventory(root: Path):
    root = Path(root).resolve()
    items=[]
    for name in CANDIDATES:
        path=root/name
        item={'file':name,'exists':path.is_file(),'parse':'NOT_TESTED','main_guard':False,'app_factories':[],'cli_functions':[]}
        if path.is_file():
            try:
                tree=ast.parse(path.read_text(encoding='utf-8-sig'),filename=name)
                item['parse']='PASS'
                for node in tree.body:
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                        if node.name.startswith(('create_','build_')) and ('app' in node.name or 'server' in node.name): item['app_factories'].append(node.name)
                        if node.name in ('main','cli','run'): item['cli_functions'].append(node.name)
                    if isinstance(node,ast.If) and isinstance(node.test,ast.Compare) and isinstance(node.test.left,ast.Name) and node.test.left.id=='__name__':
                        item['main_guard']=True
            except (OSError,UnicodeError,SyntaxError) as exc:
                item['parse']='FAIL';item['error']=type(exc).__name__
        items.append(item)
    missing=[x['file'] for x in items if not x['exists'] or x['parse']!='PASS']
    return {'version':'224.8','author':'Abdelhalim Talbi','status':'FAIL' if missing else 'PASS_WITH_UNQUALIFIED_ITEMS','entries':items,'missing_or_invalid':missing,'qualification':{'static_inventory':'PASS' if not missing else 'FAIL','application_start':'NOT_TESTED','windows_native':'NOT_TESTED','nas_migration_e2e':'NOT_TESTED'}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--output',type=Path);a=p.parse_args();result=inventory(a.root);s=json.dumps(result,indent=2,ensure_ascii=False)+'\n';print(s)
    if a.output:a.output.write_text(s,encoding='utf-8')
    return bool(result['missing_or_invalid'])
if __name__=='__main__':raise SystemExit(main())
