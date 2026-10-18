"""V187.7 standalone read-only witness daemon. No network publication endpoint."""
import argparse
import json
import os
import stat
from pathlib import Path
from ldaps_remote_witness_server import RemoteWitnessStore, make_mtls_server

class DeploymentError(ValueError):
    pass

def secure_file(path, *, secret=False):
    p=Path(path)
    if p.is_symlink() or not p.is_file():
        raise DeploymentError('UNSAFE_FILE_TYPE')
    s=p.stat()
    if s.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DeploymentError('WRITABLE_BY_GROUP_OR_OTHER')
    if secret and s.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise DeploymentError('SECRET_PERMISSIONS')
    return p

def load_config(path):
    p=secure_file(path,secret=True)
    obj=json.loads(p.read_text(encoding='utf-8'))
    keys={'host','port','db_path','certfile','keyfile','cafile','hmac_key_file'}
    if not isinstance(obj,dict) or set(obj)!=keys:
        raise DeploymentError('CONFIG_SCHEMA_INVALID')
    if not isinstance(obj['host'],str) or not obj['host'] or not isinstance(obj['port'],int) or type(obj['port']) is not int or not 1<=obj['port']<=65535:
        raise DeploymentError('LISTENER_INVALID')
    for field in ('certfile','keyfile','cafile'):
        secure_file(obj[field],secret=field=='keyfile')
    secret=secure_file(obj['hmac_key_file'],secret=True).read_bytes()
    if len(secret)<32:
        raise DeploymentError('HMAC_KEY_TOO_SHORT')
    db=Path(obj['db_path'])
    if db.is_symlink() or not db.parent.is_dir() or db.parent.is_symlink():
        raise DeploymentError('DATABASE_PATH_UNSAFE')
    if db.exists():
        secure_file(db)
    return obj,secret

def serve(config):
    if os.name!='posix' or (hasattr(os,'geteuid') and os.geteuid()==0):
        raise DeploymentError('DEDICATED_UNPRIVILEGED_ACCOUNT_REQUIRED')
    obj,key=load_config(config)
    store=RemoteWitnessStore(obj['db_path'],key=key)
    server=make_mtls_server(host=obj['host'],port=obj['port'],store=store,certfile=obj['certfile'],keyfile=obj['keyfile'],cafile=obj['cafile'])
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        server.server_close()

def main():
    parser=argparse.ArgumentParser(description='ODMM remote witness read-only daemon')
    parser.add_argument('--config',required=True)
    args=parser.parse_args()
    serve(args.config)

if __name__=='__main__':
    main()
