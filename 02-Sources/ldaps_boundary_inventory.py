"""Conservative static inventory of potentially unsafe legacy entrypoints.

An inventory is evidence for review, NOT a runtime sandbox or a proof of isolation.
"""
import ast
import hashlib
import json
import os
import stat
from pathlib import Path

class BoundaryInventoryError(ValueError):
    pass

SENSITIVE_NAMES = frozenset({"configure", "acknowledge", "recover", "set_grant", "set_role", "checkpoint", "change"})

class LegacyBoundaryInventory:
    def __init__(self, root, *, database_paths=()):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise BoundaryInventoryError("SOURCE_DIRECTORY_REQUIRED")
        self.database_paths = tuple(Path(p) for p in database_paths)

    def inspect(self):
        entries=[]
        for path in sorted(self.root.glob("ldaps_*.py")):
            if path.is_symlink():
                raise BoundaryInventoryError("SYMLINKED_SOURCE_REFUSED")
            try:
                raw=path.read_bytes()
                tree=ast.parse(raw,filename=str(path))
            except (OSError, SyntaxError, UnicodeError) as exc:
                raise BoundaryInventoryError("SOURCE_UNREADABLE_OR_INVALID") from exc
            for node in ast.walk(tree):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in SENSITIVE_NAMES:
                    entries.append({"file":path.name,"method":node.name,"line":node.lineno})
        databases=[]
        for path in self.database_paths:
            try:
                st=path.lstat()
            except FileNotFoundError:
                raise BoundaryInventoryError("DATABASE_PATH_MISSING")
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise BoundaryInventoryError("UNSAFE_DATABASE_FILE_TYPE")
            databases.append({"path":str(path),"world_readable":bool(st.st_mode & stat.S_IROTH),
                              "world_writable":bool(st.st_mode & stat.S_IWOTH),
                              "group_writable":bool(st.st_mode & stat.S_IWGRP)})
        data={"schema":1,"legacy_entrypoints":entries,"databases":databases,
              "runtime_isolation_verified":False,"execution_authorized":False,"cutover_authorized":False}
        data["sha256"]=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        return data

    def require_review(self, *, approved_hash, operator_confirmed):
        current=self.inspect()
        if operator_confirmed is not True or not isinstance(approved_hash,str) or approved_hash!=current["sha256"]:
            raise BoundaryInventoryError("EXPLICIT_CURRENT_INVENTORY_REVIEW_REQUIRED")
        if any(db["world_writable"] or db["group_writable"] for db in current["databases"]):
            raise BoundaryInventoryError("DATABASE_WRITE_EXPOSURE")
        return {"status":"INVENTORY_REVIEWED_NOT_ISOLATION_PROOF","sha256":current["sha256"],
                "runtime_isolation_verified":False,"execution_authorized":False,"cutover_authorized":False}
