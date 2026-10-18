"""Read-only static architecture, UI and packaging inventory."""
import ast, collections, json, pathlib, sys

def audit(root):
    root=pathlib.Path(root); py=list(root.glob('*.py')); names={p.stem for p in py}
    edges=[]; syntax=[]; inbound=collections.Counter(); outgoing=collections.Counter(); external=collections.Counter()
    for p in py:
        try: tree=ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p))
        except (SyntaxError,UnicodeError) as exc:syntax.append({'file':p.name,'error':str(exc)});continue
        for node in ast.walk(tree):
            mods=[]
            if isinstance(node,ast.Import):mods=[a.name.split('.')[0] for a in node.names]
            if isinstance(node,ast.ImportFrom) and node.module:mods=[node.module.split('.')[0]]
            for mod in mods:
                if mod in names:
                    edges.append((p.name,mod+'.py'));inbound[mod]+=1;outgoing[p.stem]+=1
                elif mod not in sys.stdlib_module_names:external[mod]+=1
    ui=[p.name for p in py if any(k in p.stem for k in ('portal','dashboard','cockpit','ui')) and not p.stem.startswith('test_')]
    return {'python_files':len(py),'test_files':sum(p.name.startswith('test_') for p in py),'syntax_errors':syntax,'internal_import_edges':len(edges),'most_imported_modules':inbound.most_common(25),'highest_dependency_modules':outgoing.most_common(25),'third_party_imports':external.most_common(35),'ui_modules':ui,'windows_build_scripts':[p.name for p in root.glob('*.cmd')],'observations':['Les imports ne prouvent pas une intégration fonctionnelle.','Le nombre de modules UI indique une fragmentation potentielle à analyser manuellement.','PyInstaller onefile cible le client Desktop, pas le serveur complet.','ACL SMB/NFS et migrations réelles non qualifiées.']}
if __name__=='__main__':print(json.dumps(audit(pathlib.Path(__file__).parent),indent=2,ensure_ascii=False))
