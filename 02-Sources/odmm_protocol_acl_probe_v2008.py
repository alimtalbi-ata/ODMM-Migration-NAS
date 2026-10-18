"""Fail-closed, read-only NFSv4/SMB ACL evidence collection. Author: Abdelhalim Talbi.
No passwords in argv, no shell, no implicit downgrade, no cutover authorization.
"""
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

class ProtocolACLProbeError(RuntimeError): pass

def _safe_relative(path):
    if not isinstance(path,str) or not path or "\x00" in path or "\\" in path:
        raise ProtocolACLProbeError("UNSAFE_RELATIVE_PATH")
    p=Path(path)
    if p.is_absolute() or any(x in (".","..","") for x in path.split("/")):
        raise ProtocolACLProbeError("UNSAFE_RELATIVE_PATH")
    return p

def _local_target(root,relative):
    p=_safe_relative(relative)
    base=Path(root)
    if base.is_symlink() or not base.is_dir():raise ProtocolACLProbeError("INVALID_ROOT")
    base=base.resolve(strict=True)
    target=base/p
    try: parent=target.parent.resolve(strict=True)
    except OSError as exc:raise ProtocolACLProbeError("INVALID_PARENT") from exc
    if not parent.is_relative_to(base) or target.is_symlink() or not target.exists():
        raise ProtocolACLProbeError("UNSAFE_OR_MISSING_TARGET")
    return target

def _run(command, tool, runner, timeout, protocol):
    if not tool:
        return {"status":"NOT_COLLECTED","reason":"TOOL_NOT_INSTALLED","protocol":protocol,"cutover_authorized":False}
    if not isinstance(timeout,(int,float)) or not 0<timeout<=60:raise ProtocolACLProbeError("INVALID_TIMEOUT")
    try:
        result=(runner or subprocess.run)(command,capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:raise ProtocolACLProbeError("COLLECTION_FAILED") from exc
    if result.returncode!=0:raise ProtocolACLProbeError("COLLECTION_FAILED")
    raw=result.stdout
    if not isinstance(raw,str) or not raw.strip():raise ProtocolACLProbeError("EMPTY_ACL_EVIDENCE")
    # Preserve ordering, inheritance and raw ACE representation. Never claim semantic equivalence.
    lines=[line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:raise ProtocolACLProbeError("EMPTY_ACL_EVIDENCE")
    return {"status":"COLLECTED_UNVERIFIED","protocol":protocol,"entries":lines,
            "sha256":hashlib.sha256("\n".join(lines).encode()).hexdigest(),
            "acl_equivalence_verified":False,"effective_access_verified":False,
            "cutover_authorized":False,"author":"Abdelhalim Talbi"}

def probe_nfsv4(root, relative_path, *, timeout=10, runner=None):
    target=_local_target(root,relative_path)
    tool=shutil.which("nfs4_getfacl")
    return _run([tool,"--",str(target)] if tool else [],tool,runner,timeout,"NFSV4")

def probe_smb(server,share,relative_path,*,timeout=10,runner=None):
    _safe_relative(relative_path)
    # Require strict host/share tokens: never interpolate user-controlled UNC or credentials.
    token=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
    if not all(isinstance(x,str) and token.fullmatch(x) for x in (server,share)):
        raise ProtocolACLProbeError("INVALID_SMB_ENDPOINT")
    tool=shutil.which("smbcacls")
    # Kerberos-only; no password prompt, secrets or NTLM fallback.
    cmd=[tool,f"//{server}/{share}",relative_path,"--use-kerberos=required","--no-pass"] if tool else []
    return _run(cmd,tool,runner,timeout,"SMB")

def compare_protocol_evidence(source,target):
    if not isinstance(source,dict) or not isinstance(target,dict):raise ValueError("INVALID_EVIDENCE")
    valid=all(x.get("status")=="COLLECTED_UNVERIFIED" for x in (source,target))
    same_protocol=source.get("protocol")==target.get("protocol")
    equal=valid and same_protocol and source.get("entries")==target.get("entries")
    return {"status":"RAW_ACL_MATCH_REQUIRES_ATTESTATION" if equal else "BLOCKED",
            "raw_acl_equal":bool(equal),"same_protocol":bool(same_protocol),
            "acl_equivalence_verified":False,"effective_access_verified":False,
            "cutover_authorized":False,"native_engine_modified":False}
