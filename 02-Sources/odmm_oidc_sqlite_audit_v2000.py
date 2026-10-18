"""OIDC SQLite lifecycle audit and integrity checks. Author: Abdelhalim Talbi.
Read-only audit; no changes to native migration engine.
"""
import argparse
import ast
import json
import sqlite3
from contextlib import closing
from pathlib import Path

TARGETS=("odmm_oidc_health_history_v1995.py", "odmm_oidc_alerts_v1997.py", "odmm_oidc_session_store.py")

def audit_source(path):
    source=Path(path).read_text(encoding="utf-8")
    tree=ast.parse(source,filename=str(path))
    calls=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=="connect":
            if isinstance(node.func.value,ast.Name) and node.func.value.id=="sqlite3":
                calls.append(node.lineno)
    return {"file":Path(path).name,"connect_calls":len(calls),"lines":calls,"manual_review_required":bool(calls)}

def audit_tree(root):
    root=Path(root)
    return {"author":"Abdelhalim Talbi","scope":"OIDC SQLite only", "native_engine_modified":False,
            "modules":[audit_source(root/name) for name in TARGETS if (root/name).is_file()]}

def check_database(path):
    path=Path(path)
    if not path.is_file():raise FileNotFoundError(path)
    # URI mode=ro guarantees this routine cannot create or mutate a database.
    with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True,timeout=5)) as db:
        integrity=db.execute("PRAGMA integrity_check").fetchone()[0]
        fk=db.execute("PRAGMA foreign_key_check").fetchall()
    return {"integrity":integrity,"foreign_key_violations":len(fk),"pass":integrity=="ok" and not fk}

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("--root",default=str(Path(__file__).parent));p.add_argument("--db")
    args=p.parse_args(argv)
    result=audit_tree(args.root)
    if args.db:result["database"]=check_database(args.db)
    print(json.dumps(result,indent=2))
    return 0 if not args.db or result["database"]["pass"] else 1
if __name__=="__main__":raise SystemExit(main())
