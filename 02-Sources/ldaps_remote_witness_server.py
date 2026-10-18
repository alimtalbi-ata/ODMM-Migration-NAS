"""V187.5 reference remote witness server: SQLite append-only, explicit publication.

TLS listener requires mutual certificate authentication. The database is not WORM;
protect backups, signing key and filesystem with independent administration.
"""
import hashlib
import hmac
import json
import socket
import socketserver
import sqlite3
import ssl
from pathlib import Path
from ldaps_remote_witness import canonical
from ldaps_ipc_persistent_identity import IdentityPinError

ZERO = '0' * 64

def hexmac(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

class RemoteWitnessStore:
    def __init__(self, path, *, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise IdentityPinError('REMOTE_WITNESS_KEY_TOO_SHORT')
        self.path, self.key = str(path), key
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('CREATE TABLE IF NOT EXISTS witness (seq INTEGER PRIMARY KEY, count INTEGER NOT NULL UNIQUE, last_mac TEXT NOT NULL, previous TEXT NOT NULL, entry_mac TEXT NOT NULL)')
            db.commit()
        finally: db.close()

    def _mac(self, obj):
        return hmac.new(self.key, canonical(obj), hashlib.sha256).hexdigest()

    def _verify(self, db):
        rows = db.execute('SELECT seq,count,last_mac,previous,entry_mac FROM witness ORDER BY seq').fetchall()
        prev, count = ZERO, -1
        for index, (seq, n, head, previous, mac) in enumerate(rows, 1):
            body = {'seq':seq,'count':n,'last_mac':head,'previous':previous}
            if (type(seq) is not int or seq != index or
                type(n) is not int or n < 0 or n <= count or not hexmac(head) or
                previous != prev or not hmac.compare_digest(mac, self._mac(body))):
                raise IdentityPinError('REMOTE_WITNESS_LEDGER_INVALID')
            prev, count = mac, n
        return (count, rows[-1][2]) if rows else (0, ZERO)

    def read(self):
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute('BEGIN IMMEDIATE')
            return self._verify(db)

    def publish(self, *, expected_count, expected_last_mac, new_count, new_last_mac, operator_confirmed):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if (type(expected_count) is not int or expected_count < 0 or not hexmac(expected_last_mac)
            or type(new_count) is not int or new_count <= expected_count or not hexmac(new_last_mac)):
            raise IdentityPinError('REMOTE_WITNESS_PUBLICATION_INVALID')
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute('BEGIN IMMEDIATE')
            count, head = self._verify(db)
            if (count,head) != (expected_count,expected_last_mac):
                raise IdentityPinError('REMOTE_WITNESS_STALE_PUBLICATION')
            row = db.execute('SELECT seq,entry_mac FROM witness ORDER BY seq DESC LIMIT 1').fetchone()
            seq, prev = (row[0]+1,row[1]) if row else (1,ZERO)
            body={'seq':seq,'count':new_count,'last_mac':new_last_mac,'previous':prev}
            db.execute('INSERT INTO witness VALUES (?,?,?,?,?)', (seq,new_count,new_last_mac,prev,self._mac(body)))
            db.commit()
        return {'status':'REMOTE_WITNESS_PUBLISHED','count':new_count,'cutover_authorized':False}

    def handle_read(self, request):
        if (not isinstance(request,dict) or set(request) != {'version','action','nonce'} or
            request['version'] != 1 or request['action'] != 'read' or
            not isinstance(request['nonce'],str) or len(request['nonce']) != 64 or
            any(c not in '0123456789abcdef' for c in request['nonce'])):
            raise IdentityPinError('REMOTE_WITNESS_REQUEST_INVALID')
        count,head = self.read()
        body={'version':1,'nonce':request['nonce'],'count':count,'last_mac':head}
        return {**body,'hmac_sha256':self._mac(body)}

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        line = self.rfile.readline(16385)
        if len(line) > 16384 or not line.endswith(b'\n'):
            return
        try:
            response = self.server.store.handle_read(json.loads(line))
            self.wfile.write(canonical(response)+b'\n')
        except (ValueError, TypeError, IdentityPinError, sqlite3.Error):
            return  # fail closed, no error details or state disclosed

class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def get_request(self):
        raw, addr = super().get_request()
        try:
            return self.context.wrap_socket(raw, server_side=True), addr
        except BaseException:
            raw.close()
            raise

def make_mtls_server(*, host, port, store, certfile, keyfile, cafile):
    """Construct a read-only TLS service; publication is an out-of-band operator API."""
    if not all(isinstance(p,str) and p for p in (certfile,keyfile,cafile)):
        raise IdentityPinError('REMOTE_WITNESS_MTLS_REQUIRED')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.verify_mode=ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cafile)
    context.load_cert_chain(certfile=certfile,keyfile=keyfile)
    server=_ThreadedServer((host,port),_Handler)
    server.context,server.store=context,store
    return server
