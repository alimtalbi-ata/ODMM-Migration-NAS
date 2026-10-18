"""Cross-component SQLite source inventory, read-only. Author: Abdelhalim Talbi."""
import ast
import argparse
import json
from pathlib import Path

def inventory(root):
    root=Path(root).resolve()
    findings=[]; parse_errors=[]
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git",".venv","venv","__pycache__"} for part in path.relative_to(root).parts):continue
        try:tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path))
        except (SyntaxError,UnicodeError) as exc:
            parse_errors.append({"file":str(path.relative_to(root)),"error":type(exc).__name__});continue
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):continue
            func=node.func
            direct=isinstance(func,ast.Attribute) and func.attr=="connect" and isinstance(func.value,ast.Name) and func.value.id=="sqlite3"
            imported=isinstance(func,ast.Name) and func.id=="sqlite_connect"
            if direct or imported:
                findings.append({"file":str(path.relative_to(root)),"line":node.lineno,"kind":"sqlite3.connect" if direct else "sqlite_connect alias","review_required":True})
    return {"author":"Abdelhalim Talbi","scope":"static Python source inventory; not proof of correct connection closure","native_engine_modified":False,"findings":findings,"parse_errors":parse_errors,"count":len(findings)}

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",default=str(Path(__file__).parent));p.add_argument("--output");a=p.parse_args()
    result=inventory(a.root);s=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if a.output:Path(a.output).write_text(s,encoding="utf-8")
    else:print(s,end="")
    return 1 if result["parse_errors"] else 0
if __name__=="__main__":raise SystemExit(main())
