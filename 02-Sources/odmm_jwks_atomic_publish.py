"""V198.5: publish operator-approved JWKS atomically; no remote fetching.
Author: Abdelhalim Talbi.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile
from odmm_oidc_verifier import OIDCVerifier


def publish(source, destination, *, issuer, audience):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or destination.is_symlink():
        raise PermissionError('JWKS_SYMLINK_FORBIDDEN')
    if not destination.parent.is_dir():
        raise FileNotFoundError('JWKS_DESTINATION_DIRECTORY_MISSING')
    raw = source.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('JWKS_TOO_LARGE')
    jwks = json.loads(raw)
    OIDCVerifier(issuer=issuer, audience=audience, jwks=jwks)
    fd, tmp = tempfile.mkstemp(prefix='.odmm-jwks-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600) if os.name == 'posix' else None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if destination.is_symlink():
            raise PermissionError('JWKS_SYMLINK_FORBIDDEN')
        os.replace(tmp, destination)
        if os.name == 'posix':
            dirfd = os.open(destination.parent, os.O_RDONLY)
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return destination

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Publish approved local JWKS atomically')
    p.add_argument('--source', required=True)
    p.add_argument('--destination', required=True)
    p.add_argument('--issuer', required=True)
    p.add_argument('--audience', required=True)
    a = p.parse_args()
    print(publish(a.source, a.destination, issuer=a.issuer, audience=a.audience))
