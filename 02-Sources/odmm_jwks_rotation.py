"""V197.7 controlled, offline JWKS rollover; never fetch keys from tokens/network."""
import argparse
import json
import os
import stat
import tempfile
from pathlib import Path
from odmm_oidc_verifier import OIDCVerifier


def _load(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('JWKS_FILE_INVALID')
    if os.name=='posix' and path.stat().st_mode & 0o022:
        raise ValueError('JWKS_UNSAFE_PERMISSIONS')
    return json.loads(path.read_text(encoding='utf-8'))


def plan(current_path, candidate_path, *, issuer, audience, retire=False):
    current=_load(current_path); candidate=_load(candidate_path)
    OIDCVerifier(issuer=issuer,audience=audience,jwks=current)
    OIDCVerifier(issuer=issuer,audience=audience,jwks=candidate)
    old={key['kid']:key for key in current['keys']}
    new={key['kid']:key for key in candidate['keys']}
    reused=[kid for kid in old.keys() & new.keys() if old[kid]!=new[kid]]
    if reused: raise ValueError('KID_KEY_REPLACEMENT_FORBIDDEN')
    added=sorted(new.keys()-old.keys()); removed=sorted(old.keys()-new.keys())
    if removed and not retire: raise ValueError('RETIRE_REQUIRES_EXPLICIT_APPROVAL')
    if not added and not removed: raise ValueError('NO_CHANGE')
    return {'added':added,'removed':removed,'retirement_approved':bool(retire)}


def apply(current_path,candidate_path,*,issuer,audience,retire=False):
    current=Path(current_path)
    result=plan(current,candidate_path,issuer=issuer,audience=audience,retire=retire)
    # Refuse a symlink or an unexpected existing destination; atomic replacement on same filesystem.
    content=Path(candidate_path).read_bytes()
    fd,tmp=tempfile.mkstemp(prefix='.odmm-jwks-',dir=current.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:
            f.write(content);f.flush();os.fsync(f.fileno())
        if current.is_symlink(): raise ValueError('JWKS_FILE_INVALID')
        os.replace(tmp,current)
        if hasattr(os,'O_DIRECTORY'):
            dirfd=os.open(current.parent,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return result


def main():
    parser=argparse.ArgumentParser(description='Offline pinned JWKS rotation; default dry-run')
    parser.add_argument('--current',required=True);parser.add_argument('--candidate',required=True)
    parser.add_argument('--issuer',required=True);parser.add_argument('--audience',required=True)
    parser.add_argument('--allow-retirement',action='store_true')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    fn=apply if args.apply else plan
    print(json.dumps(fn(args.current,args.candidate,issuer=args.issuer,audience=args.audience,retire=args.allow_retirement),sort_keys=True))

if __name__=='__main__': main()
